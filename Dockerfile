FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY powr3_lan.py .
# mDNS needs host networking (see compose) to see the POWR3 on the boat LAN.
CMD ["python", "-u", "powr3_lan.py"]
