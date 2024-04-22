## SUMMARY:
The aim of this project is to set a CICD pipeline that uses GitOps for the continuous delivery.

### <u>Jenkins Server</u>
In this project we shall first start with the terraform codes which creates the roles and the EC2 instance:
```python
# provider.tf
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~>5.0"
    }
  }
}
provider "aws" {
  region = "us-east-1"
}
```

```python
# main.tf
resource "aws_iam_role" "jenkins_role" {
  name = "Jenkins-terraform"
  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.jenkins_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "jenkins_profile" {
  name = "Jenkins-terraform"
  role = aws_iam_role.jenkins_role.name
}

resource "aws_security_group" "jenkins-sg" {
  name        = "Jenkins-security-group"
  description = "Open 22,80,443,8080,9000,3000"
  vpc_id = "vpc-047714d71a6ec55f4"
  # ingress rule to allow all the ports to open, we use for loop here

  ingress = [
    for port in [22,80,443,8080,9000,3000] : {
        description       = "TLS from VPC"
        from_port         = port
        to_port           = port
        protocol          = "tcp"
        cidr_blocks       = ["0.0.0.0/0"]
        ipv6_cidr_blocks  = []
        self = false
        prefix_list_ids = []
        security_groups= []
    }
  ]

  egress {
        from_port = 0 //opening all ports
        to_port  = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0c101f26f147fa7fd"
  instance_type = "t2.large"
  key_name = "jenkins"
  vpc_security_group_ids = [aws_security_group.jenkins-sg.id]
  subnet_id = "subnet-0c492c119d2652991"
  user_data = templatefile("./install_jenkins.sh", {})
  iam_instance_profile = aws_iam_instance_profile.jenkins_profile.name

  tags = {
    Name = "Jenkins-argo"
  }

  root_block_device {
    volume_size = 30
  }
}
```

The install.sh file will have all the shell script commands to install jenkins, sonar, docker, trivy, terraform, kubectl and aws cli.

```bash
#!/bin/bash
sudo apt update -y
wget -O - https://packages.adoptium.net/artifactory/api/gpg/key/public | tee /etc/apt/keyrings/adoptium.asc
echo "deb [signed-by=/etc/apt/keyrings/adoptium.asc] https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release) main" | tee /etc/apt/sources.list.d/adoptium.list
sudo apt update -y
sudo apt install temurin-17-jdk -y
/usr/bin/java --version
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | sudo tee /usr/share/keyrings/jenkins-keyring.asc > /dev/null
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/ | sudo tee /etc/apt/sources.list.d/jenkins.list > /dev/null
sudo apt-get update -y
sudo apt-get install jenkins -y
sudo systemctl start jenkins
sudo systemctl status jenkins

#install docker
sudo apt-get update
sudo apt-get install docker.io -y
sudo usermod -aG docker ubuntu  
newgrp docker
sudo chmod 777 /var/run/docker.sock
docker run -d --name sonar -p 9000:9000 sonarqube:lts-community

# install trivy
sudo apt-get install wget apt-transport-https gnupg lsb-release -y
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy -y

#install terraform
sudo apt install wget -y
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform

#install Kubectl on Jenkins
sudo apt update
sudo apt install curl -y
curl -LO https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
kubectl version --client

#install Aws cli 
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo apt-get install unzip -y
unzip awscliv2.zip
sudo ./aws/install
```

```python
#backend.tf
terraform {
  backend "s3" {
    bucket = "tetris-terraform-bucket"
    key = "jenkins-terraform.tfstate"
    region = "us-east-1"
  }
}
```
We need to create a bucket named "tetris-terraform-bucket" to store the statefile. The S3 bucket should be in place before executing this code.

The above codes created the EC2 instance, installed all the dependencies and the security group. 

![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/e7e047d5-05c0-4235-9d1a-7511c93558cd)
EC2 instance.

![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/cb09f686-b79a-439d-8d2d-88464e6f683e)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/9239d74e-db79-4e46-b99b-078582430bc1)
Security Group

![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/4fa0137d-0199-4ca4-97bc-2a7d1c48aa00)
S3 Backend

This command will reveal the password for the jenkins and this should be passed in the ec2 terminal.
 `sudo cat /var/lib/jenkins/secrets/initialAdminPassword`
Both Sonar qube and Jenkins can run as admin. `Sonar password - karthi770`
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/e22cf986-9875-4631-a0d5-30fdf2bc8ed9)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/d048cdb1-4dc5-45c6-b3f6-6d61bbeadccf)
Both sonar and Jenkins are UP and running.

#### <u> Setting up Jenkins:</u>
In Jenkins go to → Dashboard → Manage Jenkins → Plugins → Available plugins
Install → Terraform.
Now go to → Tools → we can see the terraform tab → Inside the install directory paste the path of terraform directory from the EC2 instance `which terraform` this command will give the path. Usually its `/usr/bin/terraform` but we have give only `/usr/bin/`
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/91c13a97-3e13-45cf-93b4-149c9c24e121)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/7005d87c-a536-4bbd-a70c-cffba788bf52)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/0057fd3e-8db3-4fd9-89d5-013043bc39aa)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/40425211-72f1-4e24-b235-5d51c140723d)

Building Pipeline:
```groovy
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/karthi770/Tertris_Game.git'
            }
        }
        stage('terraform init') {
            steps {
                dir('Eks-terraform'){
                    sh 'terraform init'
                }
            }
        }
        stage('terraform validate') {
            steps {
                dir('Eks-terraform'){
                    sh 'terraform validate'
                }
            }
        }
        stage('terraform plan') {
            steps {
                dir('Eks-terraform'){
                    sh 'terraform plan'
                }
            }
        }
        stage('terraform Apply/destroy') {
            steps {
                dir('Eks-terraform'){
                    sh 'terraform ${action} --auto-approve'
                }
            }
        }
    }
}
```
![image](https://github.com/karthi770/Tertris_Game/assets/102706119/4a9f6536-a0a6-433d-8edb-1648ac018b85)
Now the option is changed to Build with Parameters, we have a choice to select the action.
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/81c20f96-0902-419e-9497-058fad239ef1)
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/e42a32e8-4637-4e68-ad5c-d89b57e71e52)

Install the following plugins:
	> Temurin  (for java),  
	> Sonarqube, 
	> Node.js,
	> Owasp, 
	> Docker 

All the above tools must be configured:
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/36ca7952-f628-4c61-8ecd-6c6ed0a6d2e7)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/40508827-eb11-417f-9abd-e776ddb2e41c)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/c13f740f-377a-453a-9a0f-b2e033664e50)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/d6ea02bf-668c-4d00-84ac-669f3f43fa47)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/cee2a23f-a55c-46e3-ad0e-ff9a62fee9d2)

Sonar qube will be up and running when we first start the EC2, once we stop and start the EC2, sonar is unreachable, since it is running as a docker image. Use these command to re-start the docker.
`docker ps -a` this will show all the containers the is even stopped. `docker start [container id]` this will again start sonar qube.

Jenkins must access Sonar for code review, so a token is generated to give jenkins the access to sonar qube.  
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/d4bb3ee8-e87b-484f-a5fd-212dce347119)
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/0b186dbd-def7-4ce4-8854-ea360fe41504)
Give an id or name and save the token. Now we need to integrate Sonar and jenkins, go to manage Jenkins → select Systems:
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/a04b771d-9bdd-4319-bd8a-0c273902c290)
>[!important] 
>The public IP will change every time when we start and stop the instance.

Create a webhook in Sonarqube: Adimistration → Configuration → web hooks
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/cc45463f-ceab-4fda-9d09-80d84913f937)

Building Pipeline - 2:
```groovy
pipeline {
    agent any
    
    tools{
        jdk 'jdk-17'
        nodejs 'node16'
    }
    environment {
        SCANNER_HOME=tool 'sonar-scanner'
    }

    stages {
        stage('Check Out') {
            steps {
                git branch: 'main', url: 'https://github.com/karthi770/Tertris_Game.git'
            }
        }
        stage('SonarQube analysis') {
            steps {
                withSonarQubeEnv('sonar-server'){
                    sh '''$SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=TetrisV1 \
                    -Dsonar.projectKey=TetrisV1'''
                }
            }
        }
        // stage('Quality Gate') {
        //     steps {
        //         script {
        //         waitForQualityGate abortPipeline: false, credentialsId: 'sonar-token'
        //         }
        //     }
        // }
        stage('NPM') {
            steps {
                sh 'npm install'
            }
        }
        stage('TRIVY FS') {
            steps {
                sh 'trivy fs . > trivyfs.txt'
            }
        }
        stage('OWASP FS SCAN') {
            steps {
               dependencyCheck additionalArguments: '--scan ./ --disableYarnAudit --disableNodeAudit', odcInstallation: 'owap-check'
               dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }
        stage('Docker build and push') {
            steps {
               script {
                   withDockerRegistry(credentialsId: 'docker', toolName: 'docker') {
                       sh '''
                       docker build -t tetrisv1 .
                       docker tag tetrisv1 karthi770/tetrisv1:latest
                       docker push karthi770/tetrisv1:latest
                       '''
                   }
               }
            }
        }
        stage('TETRIS IMAGE') {
            steps {
               sh 'trivy image karthi770/tetrisv1:latest > trivyimage.txt'
            }
        }
    }
}
```
While building the pipeline, we need the setup the sonar qube, go to sonar → click on projects → click on manually → create project with some name  
![image](https://github.com/karthi770/Tertris_Game/assets/102706119/4478f580-cd02-47b9-a876-06bd6361e338)
Now the manually button has become locally. Click on that.
![image](https://github.com/karthi770/Tertris_Game/assets/102706119/3cc786f3-74dd-4bca-9b75-d6dca45f68ab)
Click on the use existing token option and enter the token generated previously in Sonarqube.
![image](https://github.com/karthi770/Tertris_Game/assets/102706119/d1b8df92-9fe0-4394-a415-b141e8b1b1ab)
![image](https://github.com/karthi770/Tertris_Game/assets/102706119/4fa4c8b5-b26e-4e37-ba0f-62edbdf170de)

sonar-scanner \
  -Dsonar.projectKey=TetrisV1 \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://3.85.84.42:9000 \
  -Dsonar.login=squ_ca4df954b64f07ab38623e24b94a863358284f0e

Quality gate pipeline Syntax:
![image](https://github.com/karthi770/Tertris_Game/assets/102706119/8f66cbbd-3002-48a3-ad9c-baf44ed8c3ca)

Add Docker credentials: Provide the dockerhub userid and password
![image](https://github.com/karthi770/Tertris_Game/assets/102706119/df8f8660-0970-4ee9-819e-246eb68209d4)
To generate script for the docker:
![image](https://github.com/karthi770/Tertris_Game/assets/102706119/f372a105-42c5-476f-983b-64376b726955)

![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/154f82c8-f86d-4602-9385-231a3786c210)

![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/51127745-ce3c-4f2a-aa1c-63443cf40d63)
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/0db749cd-3214-4544-9a07-2d11e0d5e56e)


Pipe line 3 - TETRIS V2 (Manifest and Triggers)
Github token generation → Github account settings → Developer settings → Personal Access Token (Classic) → Generate token
![image](https://github.com/karthi770/Jira_GitHub_intergration_Python/assets/102706119/7cc60f89-7c18-42f0-be08-875c026c69de)

```groovy
pipeline {
     angent any
     environment {
        GIT_REPO_NAME = "Tertris_Manifest"
        GIT_USER_NAME = "karthi770"
    }
     stages {
        stage('Checkout Code') {
          steps {
            git branch: 'main', url: 'https://github.com/karthi770/Tertris_Manifest.git'
          }
        }
    
        stage('Update Deployment File') {
          steps {
            script {
              withCredentials([string(credentialsId: 'github', variable: 'GITHUB_TOKEN')]) {
                // Determine the image name dynamically based on your versioning strategy
                NEW_IMAGE_NAME = "karthi770/tetrisv1:latest"
    
                // Replace the image name in the deployment.yaml file
                sh "sed -i 's|image: .*|image: $NEW_IMAGE_NAME|' deployment.yml"
    
                // Git commands to stage, commit, and push the changes
                sh 'git add deployment.yml'
                sh "git commit -m 'Update deployment image to $NEW_IMAGE_NAME'"
                sh "git push https://${GITHUB_TOKEN}@github.com/${GIT_USER_NAME}/${GIT_REPO_NAME} HEAD:main"
              }
            }
          }
        }
     }
 }
```
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/57d00c53-09dc-4d39-811a-d31ee834ea56)


ArgoCD installation:
https://archive.eksworkshop.com/intermediate/290_argocd/install/

```bash
aws eks update-kubeconfig --name eks_cluster_01 --region us-east-1
```
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/9b0cc380-237f-42ae-b1d2-4a085a37ea97)
```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.4.7/manifests/install.yaml
```

```
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "LoadBalancer"}}'
```
Load balancer is created.
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/e4871ac7-4f51-496b-82dd-463ea7ebacff)
Wait for 2 minutes for the load balancer to be up and running.

```bash
sudo apt install jq -y
```

```bash
export ARGOCD_SERVER=`kubectl get svc argocd-server -n argocd -o json | jq --raw-output '.status.loadBalancer.ingress[0].hostname'`
```

```bash
echo $ARGOCD_SERVER
```
This will provide the link for the load balancer.
ae2deb96b6dee42e6b5a54943e6030a5-1289219213.us-east-1.elb.amazonaws.com

Argo CD login

```bash
echo $ARGO_PWD
```
B9n0Yr9jKcbFJk8c

![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/15745334-f34c-4093-b483-2d87f6c54106)
Click on New App and give the details below:
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/fd425336-e99f-47d4-a4e1-e7b2112d2d64)
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/c6f7ea28-341a-4e55-bcbb-ff4ea242ec91)
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/3bb506c4-4815-40dc-82d7-0b9ea47c03d7)
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/8fc796aa-a950-48fd-b219-c174aecfb917)
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/85e7b432-470e-4171-aedf-aeafde1e4658)

Load Balancer is updated with 2 more load balancers.
![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/addd8577-f8b6-414a-baed-0b029e3c1d92)
a9a63be1ce1d646d992de2ef38693b1f-1954791266.us-east-1.elb.amazonaws.com

![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/39ef8676-d3a4-4167-a565-d1d61f77f9ec)

![image](https://github.com/karthi770/Tertris_Manifest/assets/102706119/7295af84-c0f3-40f9-bdab-6ed121060b1b)

Updating Version - 2

```groovy
pipeline {
    agent any
    
    tools{
        jdk 'jdk-17'
        nodejs 'node16'
    }
    environment {
        SCANNER_HOME=tool 'sonar-scanner'
    }

    stages {
        stage('Check Out') {
            steps {
                git branch: 'main', url: 'https://github.com/karthi770/Tertris_V2.git'
            }
        }
        stage('SonarQube analysis') {
            steps {
                withSonarQubeEnv('sonar-server'){
                    sh '''$SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=TetrisV2 \
                    -Dsonar.projectKey=TetrisV2'''
                }
            }
        }
        // stage('Quality Gate') {
        //     steps {
        //         script {
        //         waitForQualityGate abortPipeline: false, credentialsId: 'sonar-token'
        //         }
        //     }
        // }
        stage('NPM') {
            steps {
                sh 'npm install'
            }
        }
        stage('TRIVY FS') {
            steps {
                sh 'trivy fs . > trivyfs.txt'
            }
        }
        stage('OWASP FS SCAN') {
            steps {
               dependencyCheck additionalArguments: '--scan ./ --disableYarnAudit --disableNodeAudit', odcInstallation: 'owap-check'
               dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }
        stage('Docker build and push') {
            steps {
               script {
                   withDockerRegistry(credentialsId: 'docker', toolName: 'docker') {
                       sh '''
                       docker build -t tetrisv1 .
                       docker tag tetrisv1 karthi770/tetrisv2:latest
                       docker push karthi770/tetrisv2:latest
                       '''
                   }
               }
            }
        }
        stage('TETRIS IMAGE') {
            steps {
               sh 'trivy image karthi770/tetrisv2:latest > trivyimage.txt'
            }
        }
    }
}
```

```groovy
 pipeline {
    agent any
    
    tools{
        jdk 'jdk-17'
        nodejs 'node16'
    }
    environment {
        SCANNER_HOME=tool 'sonar-scanner'
    }

    stages {
        stage('Check Out') {
            steps {
                git branch: 'main', url: 'https://github.com/karthi770/Tertris_V2.git'
            }
        }
        stage('SonarQube analysis') {
            steps {
                withSonarQubeEnv('sonar-server'){
                    sh '''$SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=TetrisV2 \
                    -Dsonar.projectKey=TetrisV2'''
                }
            }
        }
        // stage('Quality Gate') {
        //     steps {
        //         script {
        //         waitForQualityGate abortPipeline: false, credentialsId: 'sonar-token'
        //         }
        //     }
        // }
        stage('NPM') {
            steps {
                sh 'npm install'
            }
        }
        stage('TRIVY FS') {
            steps {
                sh 'trivy fs . > trivyfs.txt'
            }
        }
        stage('OWASP FS SCAN') {
            steps {
               dependencyCheck additionalArguments: '--scan ./ --disableYarnAudit --disableNodeAudit', odcInstallation: 'owap-check'
               dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }
        stage('Docker build and push') {
            steps {
               script {
                   withDockerRegistry(credentialsId: 'docker', toolName: 'docker') {
                       sh '''
                       docker build -t tetrisv2 -f ./Tetris-V2/Dockerfile .
                       docker tag tetrisv1 karthi770/tetrisv2:latest
                       docker push karthi770/tetrisv2:latest
                       '''
                   }
               }
            }
        }
        stage('TETRIS IMAGE') {
            steps {
               sh 'trivy image karthi770/tetrisv2:latest > trivyimage.txt'
            }
        }
        stage ('trigger manifest pipeline'){
            steps{
                build job: 'TETRIS V2 (Manifest and Triggers)', wait: true
            }
        }
    }
}

```

![image](https://github.com/karthi770/Tertris_V2/assets/102706119/f24f187b-a5a1-487c-8b1f-95d72cebebf1)

![image](https://github.com/karthi770/Tertris_V2/assets/102706119/519f8a8b-ae23-4357-890e-8712f8872a3b)
