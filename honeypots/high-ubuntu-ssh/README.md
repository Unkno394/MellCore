# HoneyForge High: Ubuntu SSH VM

Первая High-ловушка — настоящая Ubuntu Server VM с OpenSSH, не Docker-контейнер.
Каждому экземпляру создаётся QCOW2 overlay поверх неизменяемого trusted base image;
при пересоздании удаляется только overlay.

SandboxManager запускает VM только на отдельном KVM-capable VPS. Guest не получает Docker
socket, libvirt socket, HoneyForge credentials или management сеть. Внешний порт публикует
host Dispatcher/NAT, guest использует isolated network.

Профиль: Ubuntu 24.04 cloud image, 2 vCPU, 2048 MiB RAM, 20 GiB overlay и настоящий
OpenSSH. Reset удаляет NAT-правила экземпляра, останавливает VM, удаляет overlay и seed;
следующий запуск создаёт чистый экземпляр.

cloud-init задаёт реальный OpenSSH и приманочные данные. При первом запуске Agent сам скачивает
официальный Ubuntu 24.04 amd64 cloud image в `/var/lib/honeyforge/images/`, сверяет SHA-256 с
официальным `SHA256SUMS`, затем скрипт create-overlay создаёт из него QCOW2 overlay и cloud-init
seed. Пользователь может передать путь к своему QCOW2 только как явный custom image.

Запуск первой VM выполняет scripts/launch.sh:

    sh scripts/launch.sh /srv/honeyforge/images/ubuntu-24.04.qcow2 INSTANCE_UUID 1488

Он создаёт isolated libvirt network, overlay и VM hf-high-INSTANCE_UUID. Скрипт reset.sh
останавливает VM, удаляет definition и рабочий overlay:

    sh scripts/reset.sh INSTANCE_UUID

Для установки recipe вместе с агентом центр получает архив:

    sh scripts/package-recipe.sh /tmp/hf-high-ubuntu-ssh.tar.gz

и запускается с `HF_HIGH_UBUNTU_RECIPE_ARCHIVE=/tmp/hf-high-ubuntu-ssh.tar.gz`.
Bootstrap распаковывает его в `/usr/local/lib/honeyforge/high-ubuntu-ssh`.
