# Contoh Jenkinsfile

Contoh berikut mengasumsikan Jenkins agent memiliki Docker CLI dan akses ke
Docker daemon. Credential `github-cred` adalah credential Jenkins tipe
**Username with password** untuk GHCR, sedangkan `imgsign-private-key` adalah
credential tipe **Secret text** yang berisi PEM private key.

Pipeline membangun dan push image aplikasi terlebih dahulu. Digest hasil push
kemudian dibentuk sebagai `repo@sha256:digest`, lalu dipakai oleh container
signer untuk sign dan verify.

```groovy
pipeline {
    agent any

    environment {
        IMAGE_NAME = 'ghcr.io/rharff/user-service'
        IMAGE_TAG  = "${BUILD_NUMBER}"
        IMAGE_FULL = "${IMAGE_NAME}:${IMAGE_TAG}"
    }

    stages {
        stage('Build and push image') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'github-cred',
                    usernameVariable: 'GHCR_USER',
                    passwordVariable: 'GHCR_TOKEN'
                )]) {
                    sh '''
                        set -eu
                        printf '%s' "$GHCR_TOKEN" | docker login ghcr.io \
                            --username "$GHCR_USER" --password-stdin
                        docker build -t "$IMAGE_FULL" .
                        docker push "$IMAGE_FULL"
                    '''
                }
            }
        }

        stage('Resolve image digest') {
            steps {
                script {
                    def digest = sh(
                        script: '''
                            docker image inspect "$IMAGE_FULL" \
                                --format='{{index .RepoDigests 0}}' |
                                sed 's/.*@//'
                        ''',
                        returnStdout: true
                    ).trim()

                    if (!digest.startsWith('sha256:')) {
                        error("Digest image tidak valid")
                    }
                    env.IMAGE_REF = "${env.IMAGE_NAME}@${digest}"
                }
            }
        }

        stage('Build signer image') {
            steps {
                sh 'make signer-image'
            }
        }

        stage('Sign and verify') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'github-cred',
                        usernameVariable: 'GHCR_USER',
                        passwordVariable: 'GHCR_TOKEN'
                    ),
                    string(
                        credentialsId: 'imgsign-private-key',
                        variable: 'IMGSIGN_PRIVATE_KEY'
                    )
                ]) {
                    sh '''
                        set -eu
                        docker run --rm \
                            -e GHCR_USER \
                            -e GHCR_TOKEN \
                            -e IMGSIGN_PRIVATE_KEY \
                            imgsign-signer:dev sign \
                            --alg ecdsa "$IMAGE_REF"
                    '''
                }
            }
        }

        stage('Verify signature') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'github-cred',
                        usernameVariable: 'GHCR_USER',
                        passwordVariable: 'GHCR_TOKEN'
                    )
                ]) {
                    sh '''
                        set -eu
                        docker run --rm \
                            -e GHCR_USER \
                            -e GHCR_TOKEN \
                            -v "$WORKSPACE/keys/pub.pem:/keys/pub.pem:ro" \
                            imgsign-signer:dev verify \
                            --alg ecdsa --pub /keys/pub.pem "$IMAGE_REF"
                    '''
                }
            }
        }
    }

    post {
        success {
            echo 'Image berhasil di-sign dan diverifikasi.'
        }
        failure {
            echo 'Pipeline gagal.'
        }
        always {
            sh 'docker image rm imgsign-signer:dev "$IMAGE_FULL" || true'
            deleteDir()
        }
    }
}
```

`keys/pub.pem` harus tersedia di workspace Jenkins, misalnya dari managed
file atau checkout repository yang aman. Jangan menyimpan private key atau
token di repository. Bentuk `-e NAMA` sengaja tidak menuliskan nilai secret;
Docker meneruskan nilai environment yang sudah disediakan Jenkins ke
container. `IMAGE_REF` wajib berbentuk `repo@sha256:digest`, bukan tag seperti
`repo:latest`.
