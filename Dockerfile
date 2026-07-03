FROM python:3.11

ENV TZ=Asia/Jakarta
RUN apt-get update && apt-get install -y tzdata
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y iputils-ping \
    && pip install --no-cache-dir -r requirements.txt

EXPOSE 5500
CMD ["python", "-u", "borg.py"]

