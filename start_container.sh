# security-opt so gdb works correctly
docker run \
    -it \
    --rm \
    --mount type=bind,source="$(pwd)"/src,target=/home/ \
    --name hbs_container \
    --security-opt seccomp=unconfined hbs_image
