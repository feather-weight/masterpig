FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt ./
<<<<<<< ours
<<<<<<< ours
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev libssl-dev rustc cargo \
    && rm -rf /var/lib/apt/lists/*

=======
=======
>>>>>>> theirs
# System build dependencies for wheels like coincurve and pynacl
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev libssl-dev rustc cargo \
    && rm -rf /var/lib/apt/lists/*
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
ENV PORT=3000
EXPOSE 3000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "3000"]
