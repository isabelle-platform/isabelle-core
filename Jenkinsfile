pipeline {
  /* Use docker image from tools/build-env folder */
  agent {
    dockerfile {
      filename 'Dockerfile_ubuntu_2404'
      dir 'tools/build-env'
    }
  }

  environment {
    /* Collect versions saved in tools/ folder */
    FULL_VERSION = sh(script: "./tools/get_version.sh full", returnStdout: true).trim()
    SHORT_VERSION = sh(script: "./tools/get_version.sh", returnStdout: true).trim()
    BRANCH_FOLDER = sh(script: "./tools/get_branch_folder.sh ${BRANCH_NAME}", returnStdout: true).trim()
  }

  stages {
    stage('Download prerequisites') {
      steps {
        dir('ttg') {
          git url: 'https://github.com/maximmenshikov/ttg.git',
              branch: 'main'
        }
      }
    }

    stage('Perform checks') {
      steps {
        /* Update Cargo */
        sh 'cargo update -p isabelle-dm'

        /* Fail if 'cargo fix' changes anything */
        sh 'cargo fix && git diff --exit-code'

        /* Fail if 'cargo fmt' changes anything */
        sh 'cargo fmt && git diff --exit-code'

        /* Fail if Cargo.toml is not updated with current version */
        sh 'cat Cargo.toml | grep ${SHORT_VERSION}'
      }
    }

    stage('Perform release checks') {
      when {
        expression {
          BRANCH_NAME == 'main'
        }
      }
      steps {
        /* Fail if tag is not updated with current version */
        sh 'git tag | grep ${SHORT_VERSION}'
      }
    }

    stage('Build for all platforms') {
      parallel {
        stage('Build (Linux)') {
          steps {
            sh 'cargo build --release'
          }
        }
      }
    }

    stage('Prepare bundle') {
      stages {
        /* Right now, we build just for Linux, that's the preferred platform for */
        stage('Prepare artifacts (branch)') {
          steps {
            sh 'mkdir -p build && (rm -rf build/* || true)'
            /* Create branch-build-linux and doc-branch-build */
            sh './tools/release.sh --out build/isabelle-core-${BRANCH_FOLDER}-${BUILD_NUMBER}-linux-x86_64.tar.xz'
            /* Copy branch-build-linux to branch-latest-linux */
            sh 'cp build/isabelle-core-${BRANCH_FOLDER}-${BUILD_NUMBER}-linux-x86_64.tar.xz build/isabelle-core-${BRANCH_FOLDER}-latest-linux-x86_64.tar.xz'
          }
        }
        stage('Prepare artifacts (versioned)') {
          when {
            expression {
              BRANCH_NAME == 'main'
            }
          }
          steps {
          /* Create versioned artifacts */
            sh 'mkdir -p build/versioned_artifacts'

            /* Copy branch-latest-linux to fullver-linux */
            sh 'cp build/isabelle-core-${BRANCH_FOLDER}-latest-linux-x86_64.tar.xz build/versioned_artifacts/isabelle-core-${FULL_VERSION}-linux-x86_64.tar.xz'
          }
        }
      }
    }
    stage('Publish artifacts') {
      parallel {
        stage('Publish artifacts (branch)') {
          steps {
            ftpPublisher alwaysPublishFromMaster: true,
                         continueOnError: false,
                         failOnError: false,
                         masterNodeName: '',
                         paramPublish: null,
                         publishers: [
                          [
                            configName: 'Isabelle Core releases',
                            transfers:
                              [[
                                asciiMode: false,
                                cleanRemote: false,
                                excludes: '',
                                flatten: false,
                                makeEmptyDirs: false,
                                noDefaultExcludes: false,
                                patternSeparator: '[, ]+',
                                remoteDirectory: "branches/${BRANCH_FOLDER}-${BUILD_NUMBER}",
                                remoteDirectorySDF: false,
                                removePrefix: 'build',
                                sourceFiles: "build/isabelle-core-*${BRANCH_FOLDER}-${BUILD_NUMBER}*.tar.xz"
                              ]],
                            usePromotionTimestamp: false,
                            useWorkspaceInPromotion: false,
                            verbose: true
                          ]
                        ]
            ftpPublisher alwaysPublishFromMaster: true,
                         continueOnError: false,
                         failOnError: false,
                         masterNodeName: '',
                         paramPublish: null,
                         publishers: [
                          [
                            configName: 'Isabelle Core releases',
                            transfers:
                              [[
                                asciiMode: false,
                                cleanRemote: false,
                                excludes: '',
                                flatten: false,
                                makeEmptyDirs: false,
                                noDefaultExcludes: false,
                                patternSeparator: '[, ]+',
                                remoteDirectory: "branches/${BRANCH_FOLDER}",
                                remoteDirectorySDF: false,
                                removePrefix: 'build',
                                sourceFiles: "build/isabelle-core-*${BRANCH_FOLDER}-latest*.tar.xz"
                              ]],
                            usePromotionTimestamp: false,
                            useWorkspaceInPromotion: false,
                            verbose: true
                          ]
                        ]
          }
        }
        stage('Publish artifacts (versioned)') {
          when {
            expression {
              BRANCH_NAME == 'main'
            }
          }
          steps {
            ftpPublisher alwaysPublishFromMaster: true,
                         continueOnError: false,
                         failOnError: false,
                         masterNodeName: '',
                         paramPublish: null,
                         publishers: [
                          [
                            configName: 'Isabelle Core releases',
                            transfers:
                              [[
                                asciiMode: false,
                                cleanRemote: false,
                                excludes: '',
                                flatten: false,
                                makeEmptyDirs: false,
                                noDefaultExcludes: false,
                                patternSeparator: '[, ]+',
                                remoteDirectory: "${FULL_VERSION}",
                                remoteDirectorySDF: false,
                                removePrefix: 'build/versioned_artifacts',
                                sourceFiles: "build/versioned_artifacts/isabelle-core-*.tar.xz"
                              ]],
                            usePromotionTimestamp: false,
                            useWorkspaceInPromotion: false,
                            verbose: true
                          ]
                        ]
          }
        }
        stage('Archive artifacts for Jenkins') {
          steps {
            archiveArtifacts artifacts: 'build/isabelle-core-*.tar.xz'
          }
        }
      }
    }
  }
  post {
    /* Send notification to Telegram */
    success {
      sh './ttg/ttg_send_notification --env --ignore-bad -- "${JOB_NAME}/${BUILD_NUMBER}: PASSED"'
    }
    failure {
      sh './ttg/ttg_send_notification --env --ignore-bad -- "${JOB_NAME}/${BUILD_NUMBER}: FAILED. See details in ${BUILD_URL}"'
    }
  }
}
