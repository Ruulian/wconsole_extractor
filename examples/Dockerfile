from nikolaik/python-nodejs

WORKDIR /home/pn/chall
COPY src .
COPY lunch.sh ./node

WORKDIR /home/pn/chall/
RUN python3 -m pip install -r python/requirements.txt

WORKDIR /home/pn/chall/node
RUN npm i

CMD ["./lunch.sh"]