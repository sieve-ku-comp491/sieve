# The forward proxy of the Java build step. Squid 6.14 in Canonical's Ubuntu 24.04 image,
# pinned by digest, with the configuration in squid.conf. Canonical names the image's tags
# after the Squid version each Ubuntu release started with, so the Ubuntu 24.04 tag says 6.6.
# The image at this digest has Ubuntu's package 6.14-0ubuntu0.24.04.5, which fixes request
# smuggling through `Transfer-Encoding: identity` (CVE-2026-61642), and `squid -v` in it prints
# "Squid Cache: Version 6.14". No tag names 6.14. To update, pull the tag, check
# `dpkg-query -W squid` and `squid -v` in it, and pin its new digest.
FROM ubuntu/squid:6.6-24.04_edge@sha256:d9c34c5ab74c6dd41cf1070d9b4221aac072e67e983527ca2d41512958f77506

COPY squid.conf /etc/squid/squid.conf

USER proxy
EXPOSE 3128
ENTRYPOINT ["/usr/sbin/squid", "-N", "-f", "/etc/squid/squid.conf"]
