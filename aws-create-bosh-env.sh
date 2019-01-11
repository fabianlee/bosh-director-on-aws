#!/bin/bash
#
# For building AWS network and computing for BOSH deployment
#
# 
# Reference
#   https://docs.aws.amazon.com/cli/latest/reference/ec2
# Query format
#   https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-output.html
#

# load aws convenience functions from same directory as this script
BIN_DIR=$(dirname ${BASH_SOURCE[0]})
source $BIN_DIR/aws-common-funcs.sh

# enforce parameter
if [ "$#" -lt 1 ]; then
  echo "USAGE: vpcName"
  echo "EXAMPLE: bosh"
  echo "Only provided $# arguments"
  exit 1
fi
vpcName=$1

# names for private bosh subnet
subnetBoshName="$vpcName-private-bosh"
sgBoshName="$vpcName-private-bosh"
cidrBosh="10.0.0.0/24"
boshGWIP="10.0.0.1"
directorIP="10.0.0.6"
directorPassword="c1oudc0w"

# names for public dmz subnet
subnetDMZName="$vpcName-public-dmz"
sgDMZName="$vpcName-public-dmz"
cidrDMZ="10.0.1.0/24"

# elastic IP for jumpbox access
jumpboxElasticIpName=$subnetDMZName
# elastic IP for NAT gateway access
natElasticIpName="$vpcName-nat"

# name of internet gateway and NAT gateway
igwName=$vpcName
natgwName=$subnetDMZName

# keypair for instances
keypairName="$vpcName"

# startup script for jumpbox
jumpboxType="t2.micro"
startupScript="jumpbox-startup.sh"


# ingress rules for subnets
# fields: description,protocol,from port,to port range,source
DMZ_INGRESS_RULES=(
 "SSH from internet,tcp,22,22,0.0.0.0/0"
 "Internal TCP,tcp,0,65535,**groupIdSelf**"
 "Internal UDP,udp,0,65535,**groupIdSelf**"
 "Internal ICMP,icmp,-1,-1,**groupIdSelf**"
)
BOSH_INGRESS_RULES=(
 "SSH from DMZ,tcp,22,22,**groupIdOther**"
 "BOSH Agent from DMZ,tcp,6868,6868,**groupIdOther**"
 "BOSH Director from DMZ,tcp,25555,25555,**groupIdOther**"
 "ICMP from DMZ,icmp,-1,-1,**groupIdOther**"
 "Internal TCP,tcp,0,65535,**groupIdSelf**"
 "Internal UDP,udp,0,65535,**groupIdSelf**"
 "Internal ICMP,icmp,-1,-1,**groupIdSelf**"
)



############ MAIN ##########################

if [ ! -f ~/.aws/credentials ]; then
  echo ERROR could not find AWS credentials at ~/.aws/credentials
  exit 99
fi
aws_access_key_id=$(grep "aws_access_key_id" ~/.aws/credentials | awk '{print $3}')
aws_secret=$(grep "aws_secret_access_key" ~/.aws/credentials | awk '{print $3}')
echo "Working on AWS with key $aws_access_key_id"

echo
echo "=== REGION ============="
showRegion region
echo "Region: $region"


echo
echo "=== VPC ============="
lookForVPC vpcId $vpcName
if [ -z $vpcId ]; then
  echo "VPC $vpcName not found, going to create"
  createVPC vpcId $vpcName "10.0.0.0/16" 
else
  echo "VPC $vpcName found, skipping creation"
fi
echo "Moving forward with VPC $vpcName with id $vpcId"


echo
echo "=== SUBNET BOSH ============="
lookForSubnet subnetBoshId $subnetBoshName
if [ -z $subnetBoshId ]; then
  echo "Subnet $subnetBoshName not found, going to create"
  createSubnet subnetBoshId $subnetBoshName $vpcId $cidrBosh "false"
else
  echo "Subnet $subnetBoshName found, skipping creation"
fi
echo "Moving forward with BOSH Subnet $subnetBoshName with id $subnetBoshId"
lookForSubnetAvailabilityField awsAvailabilityZone $subnetBoshId "AvailabilityZone"
echo "Subnet is in availability zone '$awsAvailabilityZone'"

echo
echo "=== SUBNET DMZ ============="
lookForSubnet subnetDMZId $subnetDMZName
if [ -z $subnetDMZId ]; then
  echo "Subnet $subnetDMZName not found, going to create"
  createSubnet subnetDMZId $subnetDMZName $vpcId $cidrDMZ "true"
else
  echo "Subnet $subnetDMZName found, skipping creation"
fi
echo "Moving forward with public Subnet $subnetDMZName with id $subnetDMZId"


echo
echo "=== ELASTIC IP FOR JUMPBOX ============="
lookForElasticIp jumpboxElasticIpId $jumpboxElasticIpName
if [ -z $jumpboxElasticIpId ]; then
  echo "Elastic IP for public jumpbox not found, going to create"
  createElasticIp jumpboxElasticIpId $jumpboxElasticIpName
else
  echo "Elastic IP $jumpboxElasticIpId found, skipping creation"
fi
# have elastic IP ID, so get actual IP
lookupElasticIP jumpboxElasticIP $jumpboxElasticIpName
echo "Moving forward with elastic IP for public jumpbox $jumpboxElasticIpId with IP $jumpboxElasticIP"

echo
echo "=== ELASTIC IP FOR BOSH NAT GATEWAY ============="
lookForElasticIp natElasticIpId $natElasticIpName
if [ -z $natElasticIpId ]; then
  echo "Elastic IP for private nat gateway not found, going to create"
  createElasticIp natElasticIpId $natElasticIpName
else
  echo "Elastic IP $natElasticIpId found, skipping creation"
fi
# have elastic IP ID, so get actual IP
lookupElasticIP natElasticIP $natElasticIpName
echo "Moving forward with elastic IP for private NAT gateway $natElasticIpId with IP $natElasticIP"


echo
echo "=== KEY PAIR   ============="
lookForKeyPair kpFingerprint $keypairName
if [ -z $kpFingerprint ]; then
  echo "Key pair not found, going to create"
  createKeyPair kpFingerprint $keypairName
else
  echo "Key pair $kpFingerprint found, skipping creation, loading from file"
  validateKeyMaterialFromFile $keypairName
fi
echo "Moving forward with key material from ${keypairName}.pem"


echo
echo "=== SECURITY GROUP FOR BOSH PRIVATE SUBNET  ============="
lookForSecurityGroup securityGroupBoshId $vpcId $sgBoshName
if [ -z $securityGroupBoshId ]; then
  echo "Security group for BOSH subnet not found, going to create"
  createSecurityGroup securityGroupBoshId $vpcId $sgBoshName
else
  echo "Security group for BOSH subnet found $securityGroupBoshId, skipping creation"
fi
echo "Moving forward with security group for private BOSH subnet $securityGroupBoshId"


echo
echo "=== SECURITY GROUP FOR DMZ PUBLIC SUBNET  ============="
lookForSecurityGroup securityGroupDMZId $vpcId $sgDMZName
if [ -z $securityGroupDMZId ]; then
  echo "Security group for Jumpbox subnet not found, going to create"
  createSecurityGroup securityGroupDMZId $vpcId $sgDMZName
else
  echo "Security group for Jumpbox subnet found $securityGroupDMZId, skipping creation"
fi
echo "Moving forward with security group for public Jumpbox subnet $securityGroupDMZId"



echo
echo "=== INGRESS RULES FOR BOSH PRIVATE SUBNET  ============="
showIngressRuleArray "BOSH_INGRESS_RULES"
updateSecurityGroupRules $vpcId $securityGroupBoshId $securityGroupDMZId "BOSH_INGRESS_RULES"


echo
echo "=== INGRESS RULES FOR JUMPBOX PUBLIC SUBNET  ============="
showIngressRuleArray "DMZ_INGRESS_RULES"
updateSecurityGroupRules $vpcId $securityGroupDMZId $securityGroupBoshId "DMZ_INGRESS_RULES"


echo
echo "=== IGATEWAY AND ROUTE FOR DMZ PUBLIC SUBNET  ============="
lookForInternetGateway internetGatewayId $vpcId $igwName
if [ -z $internetGatewayId ]; then
  echo "Internet gateway for vpc $igwName not found, going to create"
  createInternetGateway internetGatewayId $vpcId $igwName
else
  echo "Internet gateway for vpc $vpcName found $internetGatewayId, skipping creation"
fi
echo "Moving forward with internet gateway $internetGatewayId"

lookForRoutingTable routingId $vpcId $subnetDMZName
if [ -z $routingId ]; then
  echo "Routing table for internet gateway $igwName not found, going to create"
  createRoutingTable routingId $vpcId $subnetDMZName $internetGatewayId $subnetDMZId
else
  echo "Routing table for internet gateway $igwName found, skipping creation"
fi
echo "Moving forward with routing table $routingId for subnet $subnetDMZId $subnetDMZName"


echo
echo "=== NAT GATEWAY IN DMZ PUBLIC SUBNET  ============="
lookForNATGateway natgwId $subnetDMZId $natgwName
if [ -z $natgwId ]; then
  echo "NAT gateway for subnet $subnetDMZhName not found, going to create"
  createNATGateway natgwId $natgwName $subnetDMZId $natElasticIpId
else
  echo "NAT gateway $natgwId found for subnet $subnetDMZId, skipping creation"
fi
echo "Moving forward with NAT gateway $natgwId"
waitForState "natgw" $natgwId "available" 15 20 


echo
echo "=== ROUTE TO NAT FOR BOSH PRIVATE SUBNET  ============="
lookForRoutingTable natroutingId $vpcId $subnetBoshName
if [ -z $natroutingId ]; then
  echo "Routing table for nat gateway '$natgwName' not found, going to create"
  createRoutingTable natroutingId $vpcId $subnetBoshName $natgwId $subnetBoshId
else
  echo "Routing table for nat gateway $natgwName found, skipping creation"
fi
echo "Moving forward with routing table $natroutingId for subnet $subnetBoshId $subnetBoshName"


echo
echo "=== CREATING ENV SPECIFIC FILES ============="

# operations file for setting director sudo passwd
cat >set-director-passwd.yml << EOL
---
- type: replace
  path: /resource_pools/name=vms/env/bosh/password?
  value: ((vm_passwd))
EOL

cat >bosh-alias.sh << EOL
bosh alias-env $vpcName -e $directorIP --ca-cert <(bosh int ./creds.yml --path /director_ssl/ca)
export BOSH_CLIENT=admin
export BOSH_CLIENT_SECRET=\$(bosh int ./creds.yml --path /admin_password)
export BOSH_ENVIRONMENT=$vpcName
EOL


# executed by aws at instance startup
cat >jumpbox-startup.sh << EOL
#!/bin/bash

echo starting script >> /tmp/jumpbox-startup.sh

sudo apt-get update
sudo apt-get install -y build-essential zlibc zlib1g-dev ruby ruby-dev openssl libxslt1-dev libxml2-dev libssl-dev libreadline6 libreadline6-dev libyaml-dev libsqlite3-dev sqlite3
echo installed packages1 >> /tmp/jumpbox-startup.sh

cd /home/ubuntu

sudo apt-get install whois -y
echo -n "vm_passwd: " > vars.yml
mkpasswd -m sha-512 "$directorPassword" >> vars.yml
sudo chown ubuntu:ubuntu vars.yml

wget https://github.com/cloudfoundry/bosh-cli/releases/download/v5.4.0/bosh-cli-5.4.0-linux-amd64
mv bosh-cli-5.4.0-linux-amd64 bosh
chmod ugo+rx bosh
sudo mv bosh /usr/local/bin/.

git clone https://github.com/cloudfoundry/bosh-deployment
sudo chown -R ubuntu:ubuntu bosh-deployment

echo ending script >> /tmp/jumpbox-startup.sh
EOL



cat >do-bosh.sh <<EOL
#!/bin/bash

state="--state=state.json"
if [ -z \$1 ]; then
  action="int"
else
  action=\$1
fi

# if doing interpolate, then state is invalid option
if [ "\$action" == "int" ]; then
  state=""
fi

echo Performing \$action
bosh \$action \\
    \$state \\
    bosh-deployment/bosh.yml \\
    --vars-store=creds.yml \\
    -o bosh-deployment/aws/cpi.yml \\
    -o set-director-passwd.yml \\
    -v director_name=$vpcName \\
    -v internal_cidr=$cidrBosh \\
    -v internal_gw=$boshGWIP \\
    -v internal_ip=$directorIP \\
    -v access_key_id=$aws_access_key_id \\
    -v secret_access_key=$aws_secret \\
    -v region=$region \\
    -v az=$awsAvailabilityZone \\
    -v default_key_name=$vpcName \\
    -v default_security_groups=[$subnetBoshName] \\
    --var-file private_key=${keypairName}.pem \\
    -v subnet_id=$subnetBoshId \\
    --vars-file vars.yml \\
EOL

cat >upload-ubuntu-stemcell.sh <<EOL
bosh upload-stemcell https://bosh.io/d/stemcells/bosh-aws-xen-hvm-ubuntu-trusty-go_agent?v=3586.60
bosh stemcells
EOL

cat >update-cloud-config.sh <<EOL
bosh update-cloud-config bosh-deployment/aws/cloud-config.yml -v az=$awsAvailabilityZone -v internal_cidr=$cidrBosh -v internal_gw=$boshGWIP -v subnet_id=$subnetBoshId
EOL

cat >deploy-zookeeper.sh << EOL
wget https://raw.githubusercontent.com/fabianlee/bosh-director-on-aws/master/zookeeper.yml
bosh -e $vpcName -d zookeeper -v zookeeper_instances=3 deploy zookeeper.yml
bosh deployments
EOL




echo
echo "=== INSTANCE FOR JUMPBOX ============="
lookForLatestImage xenialId "099720109477" "ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"
if [ -z $xenialId ]; then
  echo "Could not find image for xenial 16.04, quitting"
  exit 99
else
  echo "Moving forward with xenial 16.04 image $xenialId"
fi

lookForRunningInstance jbInstanceId "$vpcName-jumpbox"
createdJumpbox=0
if [ -z $jbInstanceId ]; then
  echo "Instance for jumpbox not found '$vpcName-jumpbox', going to create"
  createInstance jbInstanceId "$vpcName-jumpbox" $jumpboxType $xenialId $subnetDMZId $securityGroupDMZId $keypairName $startupScript
  echo "going to wait for instance $jbInstanceId to be in 'active' state before moving on"
  waitForState "instance" $jbInstanceId "running" 15 10 
  echo "Jumpbox now running, but need to wait for status checks"
  waitForState "instancestatus" $jbInstanceId "ok" 15 20
  echo waiting 15 seconds for instance to stabilize
  sleep 15
  createdJumpbox=1
else
  echo "Instance for jumpbox found $jbInstanceId, skipping creation"
fi
echo "Moving forward with '$vpcName-jumpbox' $jbInstanceId"


echo
echo "=== ASSOCATE JUMPBOX WITH ELASTICIP  ============="
lookForElasticIPOnInstance jbIPAddress $jbInstanceId
if [ -z $jbIPAddress ]; then
  echo "Elastic IP not associated with $jbInstanceId, going to associate"
  associateElasticIPWithInstance $jbInstanceId $jumpboxElasticIpId
  lookForElasticIPOnInstance jbIPAddress $jbInstanceId
  # wait for association
  sleep 15 
else
  echo "Elastic IP $jbIPAddress alread associated with $jbInstanceId, continuing"
fi
echo "Moving forward with '$vpcName-jumpbox' associated to IP $jbIPAddress"


echo
echo "=== TEST SSH TO JUMPBOX ============="
sshUser="ubuntu"
# wait for ssh listener on jumpbox
while true; do
  echo trying ssh to jumpbox $jbIPAddress
  nc -vz -w 3 $jbIPAddress 22 < /dev/null
  if [ $? -eq 0 ]; then
    break
  fi
  sleep 3
done
# copy key only when jumpbox created
if [ $createdJumpbox -eq 1 ]; then
  ssh-keygen -R $jbIPAddress
  ssh -i "${keypairName}.pem" -o "StrictHostKeyChecking no" ${sshUser}@${jbIPAddress} "hostname;sudo apt-get update"
  scp -i "${keypairName}.pem" ${keypairName}.pem ${sshUser}@${jbIPAddress}:/home/ubuntu/.
fi
# copy over scripts needed to remote jumpbox
scp -i "${keypairName}.pem" {jumpbox-startup.sh,do-bosh.sh,set-director-passwd.yml,bosh-alias.sh,upload-ubuntu-stemcell.sh,update-cloud-config.sh,deploy-zookeeper.sh} ${sshUser}@${jbIPAddress}:/home/ubuntu/.
# chmod of key and remote scripts
ssh -i "${keypairName}.pem" ${sshUser}@${jbIPAddress} "cd /home/ubuntu;chmod 400 $keypairName.pem;chmod ugo+r+x *.sh"


echo
echo "=== DONE ============="
echo "for jumpbox access: ssh -i ${keypairName}.pem ${sshUser}@${jbIPAddress}"





