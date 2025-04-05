FROM node

ENV TARGET=""
ENV DURATION=""
RUN mkdir /usr/src/app
COPY src/* /usr/src/app/
COPY start.sh /
WORKDIR /usr/src/app
RUN npm install cloudscraper randomstring request

CMD /start.sh