FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY demo/requirements.txt ./demo/requirements.txt
RUN pip install -r demo/requirements.txt

COPY . .

EXPOSE 7860
ENV PORT=7860
CMD ["gunicorn", "--bind", "0.0.0.0:7860", "demo.app:app"]
