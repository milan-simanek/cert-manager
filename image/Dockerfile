FROM python:3.12-slim

WORKDIR /app

# System dependencies (none needed beyond Python)
# gosu = trusted privilege-drop helper (verifies against GPG key in the image)
COPY image/requirements.txt src/cert_manager.py image/entrypoint.sh .
RUN mv entrypoint.sh / \
 && chmod 755 /entrypoint.sh \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
          gosu \
          ca-certificates \
          gcc \
          libffi-dev \
          libssl-dev \
          python3-dev \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt \
 && groupadd -g 2000 certreaders \
 && useradd -u 1001 -G certreaders -m certmgr

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-u", "cert_manager.py"]
