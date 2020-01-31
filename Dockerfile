FROM christopherhesse/dockertest:v5

ADD env.yaml .
RUN conda env update --name env --file env.yaml
