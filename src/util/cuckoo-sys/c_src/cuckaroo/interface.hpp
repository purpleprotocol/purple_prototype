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

  C interface to C++ cuckaroo lib
*/

#ifndef MINER_INTERFACE_H
#define MINER_INTERFACE_H

#include "mean.hpp"

typedef solver_ctx SolverCtx;

extern "C" SolverCtx* new_solver_ctx(uint32_t nthreads, uint32_t ntrims, bool showcycle, bool allrounds);
extern "C" void delete_solver_ctx(SolverCtx* ctx);

extern "C" void start_miner(SolverCtx* ctx, char* header, uint64_t nonce, uint64_t* proof, uint32_t proofsize);
extern "C" int stop_miner(SolverCtx* ctx);
extern "C" bool verify_proof(char* header, uint64_t nonce, uint64_t* proof, uint32_t proofsize);
//extern "C" int found_solution(SolverCtx* ctx);

#endif