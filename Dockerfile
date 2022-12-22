FROM tiagopeixoto/graph-tool:latest
RUN pacman -S --noconfirm gcc
COPY requirements.txt /home/user/requirements.txt
USER user
RUN python -m ensurepip && python -m pip install -r /home/user/requirements.txt
WORKDIR /home/user/OSV
# COPY *.parquet ./
# COPY *.csv ./
# COPY *.py ./
