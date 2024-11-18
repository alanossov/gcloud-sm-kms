# gcloud-sm-kms
gcloud sm kms examples glued together to run a oneliner showing encrypted secrets

set env vars
```
export PROJECT_ID=
export SECRET_VERSION_ID="latest"
export SECRET_ENCRYPTED="true"
export KEY_RING=
export SECRET_ID=
export KEY=
```
run
```
docker run -e PROJECT_ID=$PROJECT_ID -e SECRET_VERSION_ID=$SECRET_VERSION_ID -e KEY_RING=$KEY_RING \
-e SECRET_ENCRYPTED=$SECRET_ENCRYPTED -e SECRET_ID=$SECRET_ID -e KEY=$KEY \
-v ~/.config/gcloud/application_default_credentials.json:/root/.config/gcloud/application_default_credentials.json \
ghcr.io/alanossov/gcloud-sm-kms:latest
```