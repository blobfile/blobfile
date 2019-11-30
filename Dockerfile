FROM christopherhesse/dockertest:v4

ADD env.yaml .
RUN conda env update --name env --file env.yaml
