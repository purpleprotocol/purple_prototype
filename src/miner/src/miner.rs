/*
  Copyright (C) 2018-2020 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.

  Parts of this file were adapted from the following file:
  https://github.com/mimblewimble/grin-miner/blob/master/cuckoo-miner/src/miner/miner.rs
*/

use crate::error::CuckooMinerError;
use crate::ffi::PluginLibrary;
use crate::plugin::{Solution, SolverCtxWrapper, SolverSolutions, SolverStats};
use crate::plugin_config::PluginConfig;
use crate::plugin_type::PluginType;
use crate::pow::proof::Proof;
use crate::shared_data::JobData;
use crate::solver_instance::SolverInstance;
use crate::verify::*;
use cfg_if::*;
use parking_lot::RwLock;
use rand::Rng;
use std::path::PathBuf;
use std::ptr::NonNull;
use crossbeam_channel::unbounded;
use crossbeam_channel::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time;
use crypto::Hash;

const SO_SUFFIX: &str = ".cuckooplugin";

cfg_if! {
    if #[cfg(all(feature = "cpu", feature = "avx"))] {
        static PLUGINS: &[&str] = &[
            "cuckaroo_cpu_avx2_24",
            "cuckaroo_cpu_avx2_25",
            "cuckaroo_cpu_avx2_26",
            "cuckaroo_cpu_avx2_27",
            "cuckaroo_cpu_avx2_28",
            "cuckaroo_cpu_avx2_29",
            "cuckaroo_cpu_avx2_30",
            "cuckaroo_cpu_avx2_31",
        ];
    } else if #[cfg(feature = "cpu")] {
        static PLUGINS: &[&str] = &[
            "cuckaroo_cpu_compat_24",
            "cuckaroo_cpu_compat_25",
            "cuckaroo_cpu_compat_26",
            "cuckaroo_cpu_compat_27",
            "cuckaroo_cpu_compat_28",
            "cuckaroo_cpu_compat_29",
            "cuckaroo_cpu_compat_30",
            "cuckaroo_cpu_compat_31",
        ];
    } else if #[cfg(feature = "gpu")] {
        static PLUGINS: &[&str] = &[
            "cuckaroo_cuda_19",
            "cuckaroo_cuda_24",
            "cuckaroo_cuda_25",
            "cuckaroo_cuda_26",
            "cuckaroo_cuda_27",
            "cuckaroo_cuda_28",
            "cuckaroo_cuda_29",
            "cuckaroo_cuda_30",
            "cuckaroo_cuda_31",
        ];
    }
}

/// Miner control Messages
#[derive(Debug, Clone)]
enum ControlMessage {
    /// Stop everything
    Stop,

    /// Stop current mining iteration, set solver threads to paused
    Pause,

    /// Resume
    Resume,

    /// Solver reporting stopped
    SolverStopped(usize),
}

#[derive(Debug, PartialEq)]
enum MinerState {
    Starting,
    Ready,
}

#[derive(Debug, PartialEq)]
enum SolverState {
    Starting,
    Paused,
    Working,
}

pub struct PurpleMiner {
    /// All of the loaded configurations
    configs: Vec<PluginConfig>,

    /// Data shared across threads
    pub shared_data: Arc<RwLock<JobData>>,

    /// Job control tx
    control_txs: Vec<Sender<ControlMessage>>,

    /// solver loop tx
    solver_loop_txs: Vec<Sender<ControlMessage>>,

    /// Solver has stopped and cleanly shutdown
    solver_stopped_rxs: Vec<Receiver<ControlMessage>>,

    /// State of the solvers
    solver_states: Vec<Arc<RwLock<SolverState>>>,

    /// The state of the miner
    miner_state: MinerState,
}

impl PurpleMiner {
    pub fn new() -> PurpleMiner {
        let configs: Vec<PluginConfig> = PLUGINS
            .iter()
            .map(|p| PluginConfig::new(get_plugins_path(), p).unwrap())
            .collect();

        let len = configs.len();
        PurpleMiner {
            configs,
            shared_data: Arc::new(RwLock::new(JobData::new(len))),
            control_txs: vec![],
            solver_loop_txs: vec![],
            solver_stopped_rxs: vec![],
            miner_state: MinerState::Starting,
            solver_states: vec![],
        }
    }

    pub fn are_solvers_started(&self) -> bool {
        self.miner_state == MinerState::Ready
    }

    fn is_starting(&self, plugin: PluginType) -> bool {
        let state = self.solver_states[plugin.repr()].read();
        *state == SolverState::Starting
    }

    fn is_paused(&self, plugin: PluginType) -> bool {
        let state = self.solver_states[plugin.repr()].read();
        *state == SolverState::Paused
    }

    fn is_working(&self, plugin: PluginType) -> bool {
        let state = self.solver_states[plugin.repr()].read();
        *state == SolverState::Working
    }

    /// Solver's instance of a thread
    fn solver_thread(
        mut solver: SolverInstance,
        instance: usize,
        shared_data: Arc<RwLock<JobData>>,
        control_rx: Receiver<ControlMessage>,
        solver_loop_rx: Receiver<ControlMessage>,
        solver_stopped_tx: Sender<ControlMessage>,
        solver_state: Arc<RwLock<SolverState>>,
    ) {
        {
            let mut s = shared_data.write();
            s.stats[instance].set_plugin_name(&solver.config.name);
        }
        // "Detach" a stop function from the solver, to let us keep a control thread going
        let ctx = solver.lib.create_solver_ctx(&mut solver.config.params);
        let control_ctx = SolverCtxWrapper(NonNull::new(ctx).unwrap());

        let stop_fn = solver.lib.get_stop_solver_instance();

        let builder = thread::Builder::new()
            .name(format!("Stop handle thread {}", instance));

        // monitor whether to send a stop signal to the solver, which should
        // end the current solve attempt below
        let stop_handle = builder.spawn(move || loop {
            thread::sleep(time::Duration::from_micros(100));

            let ctx_ptr = control_ctx.0.as_ptr();
            while let Some(message) = control_rx.iter().next() {
                match message {
                    ControlMessage::Stop => {
                        PluginLibrary::stop_solver_from_instance(stop_fn.clone(), ctx_ptr);
                        return;
                    }
                    ControlMessage::Pause => {
                        PluginLibrary::stop_solver_from_instance(stop_fn.clone(), ctx_ptr);
                    }
                    _ => {}
                };
            }
        }).unwrap();

        // Mark solver as paused
        {
            let mut solver_state = solver_state.write();
            *solver_state = SolverState::Paused;
        }

        let mut iter_count = 0;
        let mut paused = true;
        loop {
            if let Some(message) = solver_loop_rx.try_iter().next() {
                // debug!("solver_thread - solver_loop_rx got msg: {:?}", message);
                match message {
                    ControlMessage::Stop => break,
                    ControlMessage::Pause => {
                        // Mark solver as paused
                        {
                            let mut solver_state = solver_state.write();
                            *solver_state = SolverState::Paused;
                        }
                        paused = true
                    }
                    ControlMessage::Resume => {
                        // Mark solver as working
                        {
                            let mut solver_state = solver_state.write();
                            *solver_state = SolverState::Working;
                        }
                        paused = false
                    }
                    _ => {}
                }
            }
            if paused {
                thread::sleep(time::Duration::from_micros(100));
                continue;
            }
            {
                let mut s = shared_data.write();
                s.stats[instance].set_plugin_name(&solver.config.name);
            }
            let (
                header, 
                height,
                job_id,
                target_difficulty, 
            ) = {
                let data = shared_data.read();
                let header = data.header.clone();
                let height = data.height.clone();
                let job_id = data.job_id.clone();
                let target_difficulty = data.difficulty.clone();

                (header, height, job_id, target_difficulty)
            };

            // Gen random nonce
            let nonce: u64 = rand::OsRng::new().unwrap().gen();

            solver.lib.run_solver(
                ctx,
                header,
                nonce,
                1,
                &mut solver.solutions,
                &mut solver.stats,
            );

            iter_count += 1;
            let still_valid = { height == shared_data.read().height };
            if still_valid {
                let mut s = shared_data.write();
                s.stats[instance] = solver.stats.clone();
                s.stats[instance].iterations = iter_count;
                if solver.solutions.num_sols > 0 {
                    // Filter solutions that don't meet difficulty check
                    let mut filtered_sols: Vec<Solution> = vec![];
                    for i in 0..solver.solutions.num_sols {
                        filtered_sols.push(solver.solutions.sols[i as usize]);
                    }
                    let mut filtered_sols: Vec<Solution> = filtered_sols
                        .iter()
                        .filter(|s| {
                            let proof = Proof {
                                edge_bits: solver.solutions.edge_bits as u8,
                                nonce: s.nonce as u32,
                                nonces: s.proof.to_vec(),
                            };
                            proof.to_difficulty() as u64 >= target_difficulty
                        })
                        .cloned()
                        .collect();
                    for mut ss in filtered_sols.iter_mut() {
                        ss.nonce = nonce;
                        ss.id = job_id as u64;
                    }
                    solver.solutions.num_sols = filtered_sols.len() as u32;
                    for i in 0..solver.solutions.num_sols as usize {
                        solver.solutions.sols[i] = filtered_sols[i];
                    }
                    s.solutions.push(solver.solutions.clone());
                }
                if s.stats[instance].has_errored {
                    s.stats[instance].set_plugin_name(&solver.config.name);
                    // error!(
                    // 	LOGGER,
                    // 	"Plugin {} has errored, device: {}. Reason: {}",
                    // 	s.stats[instance].get_plugin_name(),
                    // 	s.stats[instance].get_device_name(),
                    // 	s.stats[instance].get_error_reason(),
                    // );
                    break;
                }
            }
            solver.solutions = SolverSolutions::default();
            thread::sleep(time::Duration::from_micros(100));
        }

        let _ = stop_handle.join();
        solver.lib.destroy_solver_ctx(ctx);
        solver.unload();
        let _ = solver_stopped_tx.send(ControlMessage::SolverStopped(instance));
    }

    /// Starts solvers, ready for jobs via job control
    pub fn start_solvers(&mut self) -> Result<(), CuckooMinerError> {
        let mut solvers = Vec::new();
        for c in self.configs.clone() {
            solvers.push(SolverInstance::new(c)?);
        }
        let mut i = 0;
        for s in solvers {
            let sd = self.shared_data.clone();
            let (control_tx, control_rx) = unbounded::<ControlMessage>();
            let (solver_tx, solver_rx) = unbounded::<ControlMessage>();
            let (solver_stopped_tx, solver_stopped_rx) = unbounded::<ControlMessage>();
            let solver_state = Arc::new(RwLock::new(SolverState::Starting));
            let solver_state_clone = solver_state.clone();
            self.control_txs.push(control_tx);
            self.solver_loop_txs.push(solver_tx);
            self.solver_stopped_rxs.push(solver_stopped_rx);
            self.solver_states.push(solver_state);
            
            let builder = thread::Builder::new()
                .name(format!("Solver thread {}", i));

            builder.spawn(move || {
                let _ = PurpleMiner::solver_thread(
                    s,
                    i,
                    sd,
                    control_rx,
                    solver_rx,
                    solver_stopped_tx,
                    solver_state_clone,
                );
            }).unwrap();
            i += 1;
        }
        self.miner_state = MinerState::Ready;
        Ok(())
    }

    /// An asynchronous -esque version of the plugin miner, which takes
    /// parts of the header and the target difficulty as input, and begins
    /// asynchronous processing to find a solution. The loaded plugin is
    /// responsible
    /// for how it wishes to manage processing or distribute the load. Once
    /// called
    /// this function will continue to find solutions over the target difficulty
    /// for the given inputs and place them into its output queue until
    /// instructed to stop.
    pub fn notify(
        &mut self,
        //job_id: u32, // Job id
        height: u64, // Job height
        header: &[u8],
        difficulty: u64, /* The target difficulty, only sols greater than this difficulty will
                          * be returned. */
        plugin: PluginType, // Which plugin to use
    ) -> Result<(), CuckooMinerError> {
        let mut sd = self.shared_data.write();

        #[cfg(feature = "test")]
        {
            if let PluginType::Cuckoo0 = plugin {
                info!("Mining header {} with height {} in test mode", hex::encode(header), height);
        
                //sd.job_id = job_id;
                sd.height = height;
                sd.header = header.to_vec();
                sd.difficulty = difficulty;
                sd.solutions = vec![SolverSolutions::default()];

                return Ok(())
            }
        }

        #[cfg(not(feature = "test"))]
        {
            if let PluginType::Cuckoo0 = plugin {
                panic!("This plugin type can only be used in test mode!");
            }
        }

        let mut paused = self.is_paused(plugin);
        if height != sd.height && !paused {
            // stop/pause any existing jobs if job is for a new
            // height
            self.pause_solvers();
            paused = true;
        }

        info!("Mining header {} with height {}", hex::encode(header), height);
        
        //sd.job_id = job_id;
        sd.height = height;
        sd.header = header.to_vec();
        sd.difficulty = difficulty;
        if paused {
            self.resume_solver(plugin.repr());
        }
        Ok(())
    }

    /// Returns the current height of the header being mined.
    /// 
    /// Returns `None` if the miner is in stand-by.
    pub fn current_height(&self, plugin: PluginType) -> Option<u64> {
        #[cfg(feature = "test")] 
        { 
            // Don't check solver state in test mode
            if let PluginType::Cuckoo0 = plugin {
                let sd = self.shared_data.read();
                return Some(sd.height);
            }
        }

        #[cfg(not(feature = "test"))]
        {
            if let PluginType::Cuckoo0 = plugin {
                panic!("This plugin type can only be used in test mode!");
            }
        }

        if *self.solver_states[plugin.repr()].read() == SolverState::Paused {
            return None;
        }
        
        let sd = self.shared_data.read();
        Some(sd.height)
    }

    /// Returns the hash of the current header being mined.
    /// 
    /// Returns `None` if the miner is in stand-by.
    pub fn current_header_hash(&self, plugin: PluginType) -> Option<Hash> {
        #[cfg(feature = "test")] 
        { 
            // Don't check solver state in test mode
            if let PluginType::Cuckoo0 = plugin {
                let sd = self.shared_data.read();
                return Some(crypto::hash_slice(&sd.header));
            }
        }

        #[cfg(not(feature = "test"))]
        {
            if let PluginType::Cuckoo0 = plugin {
                panic!("This plugin type can only be used in test mode!");
            }
        }

        if *self.solver_states[plugin.repr()].read() == SolverState::Paused {
            return None;
        }
        
        let sd = self.shared_data.read();
        Some(crypto::hash_slice(&sd.header))
    }

    /// Returns solutions if currently waiting.
    pub fn get_solutions(&self) -> Option<SolverSolutions> {
        let has_solutions = {
            let s = self.shared_data.read();
            s.solutions.len() > 0
        };  

        if has_solutions {
            let mut s = self.shared_data.write();
            s.solutions.pop()
        } else {
            None
        }
    }

    /// get stats for all running solvers
    pub fn get_stats(&self) -> Result<Vec<SolverStats>, CuckooMinerError> {
        let s = self.shared_data.read();
        Ok(s.stats.clone())
    }

    /// #Description
    ///
    /// Stops the current job, and signals for the loaded plugin to stop
    /// processing and perform any cleanup it needs to do.
    ///
    /// #Returns
    ///
    /// Nothing

    pub fn stop_solvers(&self) {
        for t in self.control_txs.iter() {
            let _ = t.send(ControlMessage::Stop);
        }
        for t in self.solver_loop_txs.iter() {
            let _ = t.send(ControlMessage::Stop);
        }
        // debug!("Stop message sent");
    }

    /// Tells current solvers to stop and wait
    pub fn pause_solvers(&self) {
        for t in self.control_txs.iter() {
            let _ = t.send(ControlMessage::Pause);
        }
        for t in self.solver_loop_txs.iter() {
            let _ = t.send(ControlMessage::Pause);
        }
        // debug!("Pause message sent");
    }

    /// Tells current solvers to stop and wait
    pub fn resume_solvers(&self) {
        for t in self.control_txs.iter() {
            let _ = t.send(ControlMessage::Resume);
        }
        for t in self.solver_loop_txs.iter() {
            let _ = t.send(ControlMessage::Resume);
        }
        // debug!("Resume message sent");
    }

    /// Tells a specific solver to resume
    pub fn resume_solver(&self, solver_idx: usize) {
        let t = &self.solver_loop_txs[solver_idx];
        let _ = t.send(ControlMessage::Resume);
    }

    /// block until solvers have all exited
    pub fn wait_for_solver_shutdown(&self) {
        for r in self.solver_stopped_rxs.iter() {
            while let Some(message) = r.iter().next() {
                match message {
                    ControlMessage::SolverStopped(i) => {
                        // debug!("Solver stopped: {}", i);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn get_plugins_path() -> PathBuf {
    let mut p_path = std::env::current_exe().unwrap();
    p_path.pop();
    //p_path.pop();
    p_path.push("plugins");
    p_path
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn it_finds_and_verifies_proofs() {
    //     let mut miner = PurpleMiner::new();
    //     miner.start_solvers().unwrap();
    //     let mut count = 0;

    //     loop {
    //         thread::sleep_ms(1000);

    //         if !miner.is_starting(PluginType::Cuckoo19) && !miner.is_working(PluginType::Cuckoo19) {
    //             // Start miner
    //             miner.notify(0, 1, b"", 0, PluginType::Cuckoo19).unwrap();
    //         }

    //         if let Some(solution) = miner.get_solutions() {
    //             let solution = solution.sols[0];
    //             let nonce = solution.nonce;
    //             let proof = Proof::new(solution.to_u64s(), 19);

    //             assert!(verify(b"", nonce as u32, &proof).is_ok());
    //             break;
    //         }

    //         // Kill test if running for more than 60 seconds
    //         if count > 60 {
    //             assert!(false);
    //         }

    //         count += 1;
    //     }
    // }
}
