# The forward proxy of the Java build step. Squid 6.14 in Canonical's Ubuntu 24.04 image,
# pinned by digest, with the configuration in squid.conf. Canonical names the image's tags
# after the Squid version each Ubuntu release started with, so the Ubuntu 24.04 tag says 6.6.
# The image at this digest has Ubuntu's package 6.14-0ubuntu0.24.04.2, and `squid -v` in it
# prints "Squid Cache: Version 6.14". No tag names 6.14.
FROM ubuntu/squid:6.6-24.04_edge@sha256:8a3baed477e2c282ab8aa5edad442f69873246964f225c5c2ae8364b6610963c

COPY squid.conf /etc/squid/squid.conf

USER proxy
EXPOSE 3128
ENTRYPOINT ["/usr/sbin/squid", "-N", "-f", "/etc/squid/squid.conf"]
