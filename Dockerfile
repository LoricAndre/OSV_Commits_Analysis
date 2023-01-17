FROM tiagopeixoto/graph-tool:latest
RUN sed -i 's/^SigLevel.*$/SigLevel = Optional TrustAll/' /etc/pacman.conf
RUN pacman -S --noconfirm gcc postgresql git make
RUN git clone https://github.com/zvelo/cmph.git /cmph
RUN cd /cmph && ./configure && make && make install
COPY requirements.txt /home/user/requirements.txt
USER user
RUN python -m ensurepip && python -m pip install -r /home/user/requirements.txt
WORKDIR /home/user/OSV
