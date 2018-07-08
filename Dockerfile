FROM ubuntu
RUN apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y libssl-dev && \
    apt-get install -y valgrind && \
    apt-get install -y wget && \
    wget https://github.com/USCiLab/cereal/archive/v1.2.2.tar.gz && \
    tar -xvf v1.2.2.tar.gz && \
    rm v1.2.2.tar.gz && \
    mkdir /home/include && \
    mv cereal-1.2.2/include/cereal /usr/local/include/cereal && \
    rm -rf cereal-1.2.2 && \
    wget https://raw.githubusercontent.com/catchorg/Catch2/master/single_include/catch2/catch.hpp && \
    mv catch.hpp /usr/local/include
WORKDIR home/