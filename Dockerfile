FROM swift:6.0.2-jammy

# Dependencies required for building mkcheck2
RUN apt-get update && apt-get install -y \
  cmake ninja-build wget libbpf-dev linux-tools-common linux-tools-generic linux-tools-`uname -r`

# Install LLVM not to use the one in the Swift toolchain
# because it does not include ebpf target support.
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main" > /etc/apt/sources.list.d/llvm.list && \
  apt-get update && apt-get install -y clang-18
ENV PATH="/usr/lib/llvm-18/bin:${PATH}"

ADD ./ /tmp/mkcheck2
ARG MKCHECK2_BUILD_ARGS="-c release --static-swift-stdlib"
RUN cd /tmp/mkcheck2 && ./build.sh $MKCHECK2_BUILD_ARGS

