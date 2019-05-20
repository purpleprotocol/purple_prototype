/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

/// Initializes a new `SolverCtx`.
extern "C" SolverCtx* new_solver_ctx(nthreads: u32, ntrims: u32, showcycle: bool, allrounds: bool) {
    SolverParams params;
    params.nthreads = nthreads;
    params.ntrims = ntrims;
    params.showcycle = showcycle;
    params.allrounds = allrounds;

    return create_solver_ctx(&params);
}

extern "C" void delete_solver_ctx(SolverCtx* ctx) {
    destroy_solver_ctx(ctx);
}

/// Starts a miner process.
extern "C" void start_miner(SolverCtx* ctx, char* header, uint64_t* nonce, uint64_t* proof, uint64_t proofsize, uint64_t range) {
    assert(range > 1);

    stop_solver(ctx);
	run_solver(ctx, header, sizeof(header), nonce, range, NULL, NULL);
}

/// Stops the current miner process. Returns 0 if succesful.
/// Returns -1 if there is no process that is currently running.
extern "C" int stop_miner(SolverCtx* ctx) {
    stop_solver(ctx);
}

/// Verifies a proof
extern "C" bool verify(SolverCtx* ctx, char* header, uint64_t nonce, uint64_t* proof, uint64_t proofsize) {
    return false;
}

// /// Returns 0 if the miner has stopped and has found a solution.
// /// Returns 1 if this is not the case.
// /// Returns -1 if there is no started process.  
// extern "C" int found_solution(SolverCtx* ctx) {

// }