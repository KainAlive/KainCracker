pipeline {
  agent any
  stages {
    stage('Starting') {
      steps {
        echo 'Jenkins Staring'
      }
    }

    stage('Docker') {
      steps {
        build 'Docker'
        dockerNode(image: 'golang')
      }
    }

  }
}