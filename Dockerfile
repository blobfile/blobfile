FROM christopherhesse/dockertest:v3

ADD env.yaml .
RUN conda env update --name env --file env.yaml
ENV PATH=/root/miniconda3/envs/env/bin:$PATH
