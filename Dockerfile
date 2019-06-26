FROM ubuntu:bionic-20190122
RUN apt-get update
RUN apt-get install --yes curl

# python
RUN curl -O https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86_64.sh
RUN sh Miniconda3-latest-Linux-x86_64.sh -b
ENV PATH=/root/miniconda3/bin:$PATH
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ADD env.yaml .
RUN conda env update --name env --file env.yaml
ENV PATH=/root/miniconda3/envs/env/bin:$PATH
