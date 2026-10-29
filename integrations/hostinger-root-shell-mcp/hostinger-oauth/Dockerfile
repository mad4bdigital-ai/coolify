FROM node:24-bookworm-slim
RUN npm install --global --ignore-scripts @hostinger/mcp@3.4.0
RUN groupadd -g 10001 hostinger && useradd --uid 10001 --gid 10001 --create-home hostinger
USER hostinger
ENV HOME=/home/hostinger
WORKDIR /home/hostinger
# The official Hostinger OAuth login uses stdio and a browser redirect.
# No HTTP port is exposed and login must be completed by the operator.
ENTRYPOINT ["hostinger-hosting-mcp"]
