# A small plug-in for the runner's tests. It reads what to do from /src/mode, so one image
# covers success, crashes, timeouts, bad output, network attempts and the build step.
FROM busybox:1.37.0

COPY run.sh /run.sh
RUN chmod 755 /run.sh

USER 10001:10001
ENTRYPOINT ["/run.sh"]
