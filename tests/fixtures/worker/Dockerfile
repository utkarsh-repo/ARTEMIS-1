# Build this fixture only for an isolated, disposable integration-test host.
# The image is pushed to a local test registry and then referenced by digest.
FROM python:3.12-slim
COPY worker.py /opt/artemis/worker.py
RUN chmod 0555 /opt/artemis/worker.py
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python3", "/opt/artemis/worker.py"]
