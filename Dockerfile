FROM certbot/certbot

COPY . src/certbot-dns-zhujike

RUN pip install --no-cache-dir --editable src/certbot-dns-zhujike
