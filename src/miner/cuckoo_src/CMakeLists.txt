cmake_minimum_required(VERSION 3.2)
project (Cuckoo)

set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins)

if (WIN32) 
	find_package(Threads REQUIRED)
	set(CMAKE_USE_WIN32_THREADS_INIT 1)
	set(CXX_STANDARD 11)
	set(CXX_STANDARD_REQUIRED 1)
	set (FLAGS "-I. ${CPPFLAGS}")
else()
	set (CMAKE_CXX_FLAGS "--std=c++11")
	set (OPT "-O3")
	set (DOPT "-DPREFETCH")
	set (FLAGS "-Wno-format -Wno-deprecated-declarations -D_POSIX_C_SOURCE=200112L ${OPT} ${DOPT} -I. ${CPPFLAGS} -pthread")
	set (GPP_FLAGS "-march=native -m64 ${FLAGS}")
	set (CFLAGS "-Wno-format -fomit-frame-pointer ${OPT}")
	set (GCC_FLAGS "-m64 -std=gnu11 ${CFLAGS}")
endif()

set (CUDA_HOST_COMPILER_OVERRIDE $ENV{CUDA_HOST_COMPILER})
set (SKIP_CUCKATOO_GPU $ENV{SKIP_CUCKATOO_GPU})

#blake2b prerequisite
set (BLAKE_2B "cuckoo/src/crypto/blake2b-ref.c")

#common to all plugins
set (PLUGIN_BUILD_FLAGS "-DC_CALL_CONVENTION=1 -DSQUASH_OUTPUT=1")

#build CPU target
function (build_cpu_target sources target props)
	add_library(${target} SHARED ${sources})
	set_target_properties(${target} PROPERTIES COMPILE_FLAGS "${GPP_FLAGS} ${props} ${PLUGIN_BUILD_FLAGS}" PREFIX "" SUFFIX ".cuckooplugin")
endfunction()

function (build_cuda_target sources target props)
	if (BUILD_CUDA_PLUGINS)
		include("cmake/find_cuda.cmake")
		if (CUDA_FOUND)
			set (CUDA_PROPAGATE_HOST_FLAGS ON)
			cuda_add_library (${target} SHARED ${sources} OPTIONS "${props} ${PLUGIN_BUILD_FLAGS}")
			set_target_properties(${target} PROPERTIES PREFIX "" SUFFIX ".cuckooplugin")
		endif (CUDA_FOUND)
	endif (BUILD_CUDA_PLUGINS)
endfunction()

set (AR_CPU_SRC
			cuckoo/src/cuckaroo/cuckaroo.hpp
			cuckoo/src/cuckaroo/bitmap.hpp
			cuckoo/src/cuckaroo/graph.hpp
			cuckoo/src/threads/barrier.hpp
			cuckoo/src/crypto/siphash.hpp
			cuckoo/src/cuckaroo/mean.hpp
			cuckoo/src/cuckaroo/mean.cpp
			${BLAKE_2B})

if (WIN32)
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_19 "-DXBITS=2 -DNSIPHASH=4 -DEDGEBITS=19 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_19 "-arch:AVX2 -MD -DXBITS=2 -DNSIPHASH=8 -DEDGEBITS=19 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_24 "-DXBITS=4 -DNSIPHASH=1 -DEDGEBITS=24 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_24 "-DXBITS=4 -arch:AVX2 -MD -DNSIPHASH=8 -DEDGEBITS=24 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_25 "-DXBITS=5 -DNSIPHASH=1 -DEDGEBITS=25 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_25 "-DXBITS=5 -arch:AVX2 -MD -DNSIPHASH=8 -DEDGEBITS=25 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_26 "-DNSIPHASH=1 -DXBITS 5 -DEDGEBITS=26 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_26 "-arch:AVX2 -MD -DXBITS 5 -DNSIPHASH=8 -DEDGEBITS=26 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_27 "-DNSIPHASH=1 -DXBITS 6 -DEDGEBITS=27 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_27 "-arch:AVX2 -MD -DXBITS 6 -DNSIPHASH=8 -DEDGEBITS=27 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_28 "-DNSIPHASH=1 -DEDGEBITS=28 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_28 "-arch:AVX2 -MD -DNSIPHASH=8 -DEDGEBITS=28 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_29 "-DNSIPHASH=1 -DEDGEBITS=29 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_29 "-arch:AVX2 -MD -DNSIPHASH=8 -DEDGEBITS=29 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_30 "-DXBITS=8 -DNSIPHASH=1 -DEXPANDROUND=10 -DCOMPRESSROUND=22 -DEDGEBITS=3 -DEDGEBITS=30 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_30 "-DXBITS=8 -arch:AVX2 -MD -DEXPANDROUND=10 -DCOMPRESSROUND=22 -DEDGEBITS=3 -DNSIPHASH=8 -DEDGEBITS=30 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_31 "-DXBITS=8 -DNSIPHASH=1 -DEXPANDROUND=10 -DCOMPRESSROUND=22 -DEDGEBITS=3 -DEDGEBITS=31 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_31 "-DXBITS=8 -arch:AVX2 -MD -DEXPANDROUND=10 -DCOMPRESSROUND=22 -DEDGEBITS=3 -DNSIPHASH=8 -DEDGEBITS=31 -DSAVEEDGES")
else()
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_19 "-DXBITS=2 -DNSIPHASH=4 -DEDGEBITS=19 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_19 "-mavx2 -DXBITS=2 -DNSIPHASH=8 -DEDGEBITS=19 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_24 "-DXBITS=4 -mno-avx2 -DNSIPHASH=4 -DEDGEBITS=24 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_24 "-DXBITS=4 -mavx2 -DNSIPHASH=8 -DEDGEBITS=24 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_25 "-DXBITS=5 -mno-avx2 -DNSIPHASH=4 -DEDGEBITS=25 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_25 "-DXBITS=5 -mavx2 -DNSIPHASH=8 -DEDGEBITS=25 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_26 "-DXBITS=5 -mno-avx2 -DNSIPHASH=4 -DEDGEBITS=26 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_26 "-DXBITS=5 -mavx2 -DNSIPHASH=8 -DEDGEBITS=26 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_27 "-DXBITS=6 -mno-avx2 -DNSIPHASH=4 -DEDGEBITS=27 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_27 "-DXBITS=6 -mavx2 -DNSIPHASH=8 -DEDGEBITS=27 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_28 "-mno-avx2 -DNSIPHASH=4 -DEDGEBITS=28 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_28 "-mavx2 -DNSIPHASH=8 -DEDGEBITS=28 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_29 "-mno-avx2 -DNSIPHASH=4 -DEDGEBITS=29 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_29 "-mavx2 -DNSIPHASH=8 -DEDGEBITS=29 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_30 "-mno-avx2 -DXBITS=8 -DNSIPHASH=4 -DEXPANDROUND=10 -DCOMPRESSROUND=22 -DEDGEBITS=30 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_30 "-mavx2 -DXBITS=8 -DNSIPHASH=8 -DEXPANDROUND=10 -DCOMPRESSROUND=22 -DEDGEBITS=30 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_compat_31 "-mno-avx2 -DXBITS=8 -DNSIPHASH=4 -DEXPANDROUND=10 -DCOMPRESSROUND=22 -DEDGEBITS=31 -DSAVEEDGES")
	build_cpu_target("${AR_CPU_SRC}" cuckaroo_cpu_avx2_31 "-mavx2 -DXBITS=8 -DNSIPHASH=8 -DEXPANDROUND=10 -DCOMPRESSROUND=22 -DEDGEBITS=31 -DSAVEEDGES")
endif()

set (AR_CUDA_SRC cuckoo/src/cuckaroo/mean.cu ${BLAKE_2B} )

build_cuda_target("${AR_CUDA_SRC}" cuckaroo_cuda_19 "-DEPS_A=4 -DEPS_B=3 -DIDXSHIFT=2 -DEDGEBITS=19")
build_cuda_target("${AR_CUDA_SRC}" cuckaroo_cuda_24 "-DEDGEBITS=24")
build_cuda_target("${AR_CUDA_SRC}" cuckaroo_cuda_25 "-DEDGEBITS=25")
build_cuda_target("${AR_CUDA_SRC}" cuckaroo_cuda_26 "-DEDGEBITS=26")
build_cuda_target("${AR_CUDA_SRC}" cuckaroo_cuda_27 "-DEDGEBITS=27")
build_cuda_target("${AR_CUDA_SRC}" cuckaroo_cuda_28 "-DEDGEBITS=28")
build_cuda_target("${AR_CUDA_SRC}" cuckaroo_cuda_29 "-DEDGEBITS=29")
build_cuda_target("${AR_CUDA_SRC}" cuckaroo_cuda_30 "-DEDGEBITS=30")
build_cuda_target("${AR_CUDA_SRC}" cuckaroo_cuda_31 "-DEDGEBITS=31")