# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "null_resource" "docker_compose_up" {
  triggers = {
    always_run = "${timestamp()}"
  }

  // Running down at the beginning so terraform apply can be executed multiple times to pick up on latest docker-compose.yaml changes
  provisioner "local-exec" {
    command = "docker-compose -f ./docker-compose.yml down && docker-compose -f ./docker-compose.yml up -d"
    when    = create
  }
}

resource "null_resource" "docker_compose_down" {
  triggers = {
    always_run = "${timestamp()}"
  }

  provisioner "local-exec" {
    command = "docker-compose -f ./docker-compose.yml down"
    when    = destroy
  }
}

resource "local_file" "setup_environment_file" {
  filename = "local_environment_setup.sh"
  content = <<EOF
export TEST_REDIS_HOST=localhost &&\
export TEST_REDIS_PORT=6379 &&\
export TEST_REDIS_USERNAME=us4rn4m3 &&\
export TEST_REDIS_PASSWORD=user-pa55w0rd
EOF
}