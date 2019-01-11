

# If last call to aws failed, then fatal exit
function checkForAWSError() {
  code=$1
  if [ $code != 0 ]; then
    echo "================================================"
    echo "ERROR: Non 0 exit code from aws cli, exiting"
    echo "================================================"
    exit 99
  fi
}

# If last call to aws failed, then warn but continue
function allowForAWSError() {
  code=$1
  if [ $code != 0 ]; then
    echo "================================================"
    echo "WARNING: failed exit code $code from aws cli, continue processing"
    echo "================================================"
    return $code
  fi
  # always returns OK
  return 0
}

# lookup region connected to from configuration
function showRegion() {
  local  __resultvar=$1
  lookingFor=$2

  echo "Looking for region being used from configuration"
  myRegion=$(aws configure get region)
  checkForAWSError $?

  eval $__resultvar="$myRegion"
}



# given a VPC name, find ID
# empty if not found
function lookForVPC() {
  local  __resultvar=$1
  lookingFor=$2

  echo "Looking for vpc named: $lookingFor"
  vpcId=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=$lookingFor" --query "Vpcs[].VpcId" --output text)
  checkForAWSError $?

  eval $__resultvar="$vpcId"
}

# creates VPC and tags with name
# returns ID of VPC created
function createVPC() {
  local  __resultvar=$1
  vpcName=$2
  cidr=$3

  # create VPC
  vpcId=$(aws ec2 create-vpc --cidr-block "$cidr" --query 'Vpc.{VpcId:VpcId}' --output text)
  checkForAWSError $?

  # tag with name
  aws ec2 create-tags --resources $vpcId --tags "Key=Name,Value=$vpcName"
  checkForAWSError $?

 eval $__resultvar="$vpcId"
}


# given a subnet name, find ID
# empty if not found
function lookForSubnet() {
  local  __resultvar=$1
  lookingFor=$2

  echo "Looking for subnet named: $lookingFor"
  subnetId=$(aws ec2 describe-subnets --filters "Name=tag:Name,Values=$lookingFor" --query "Subnets[].SubnetId" --output text)
  checkForAWSError $?

  eval $__resultvar="$subnetId"
}

# given a subnet id, find field value
# empty if not found
function lookForSubnetAvailabilityField() {
  local  __resultvar=$1
  subnetId=$2
  fieldName=$3

  echo "Looking for field $fieldName in subnet $subnetId"
  fieldValue=$(aws ec2 describe-subnets --subnet-id $subnetId --query "Subnets[].${fieldName}" --output text)
  checkForAWSError $?

  eval $__resultvar="$fieldValue"
}


# creates subnet and tags with name
# returns ID of subnet created
function createSubnet() {
  local  __resultvar=$1
  subnetName=$2
  vpcId=$3
  cidr=$4
  mapPublicIPOnLaunch=$5

  # create subnet
  subnetId=$(aws ec2 create-subnet --vpc-id $vpcId --cidr-block "$cidr" --query 'Subnet.{Subnet:SubnetId}' --output text)
  checkForAWSError $?

  # tag with name
  aws ec2 create-tags --resources $subnetId --tags "Key=Name,Value=$subnetName"
  checkForAWSError $?

  # does this subnet map public IP on default?
  if [ "$mapPublicIPOnLaunch" == "true" ]; then
    echo "Setting $subnetName with mapping to public IP on launch"
    aws ec2 modify-subnet-attribute --subnet-id $subnetId --map-public-ip-on-launch
  fi

 eval $__resultvar="$subnetId"
}



# given an elastic IP name, find ID
# empty if not found
function lookForElasticIp() {
  local  __resultvar=$1
  lookingFor=$2

  echo "Looking for elastic IP named: $lookingFor"
  allocationId=$(aws ec2 describe-addresses --filters "Name=tag:Name,Values=$lookingFor" --query "Addresses[].AllocationId" --output text)
  checkForAWSError $?

  eval $__resultvar="$allocationId"
}

# creates elastic IP tagged with name
# returns ID of elastic IP created
function createElasticIp() {
  local  __resultvar=$1
  elasticIpName=$2

  # create subnet
  allocationId=$(aws ec2 allocate-address --domain vpc --query AllocationId --output text)
  checkForAWSError $?

  # tag with name
  aws ec2 create-tags --resources $allocationId --tags "Key=Name,Value=$elasticIpName"
  checkForAWSError $?

 eval $__resultvar="$allocationId"
}

# gets elastic IP given tagged name
function lookupElasticIP() {
  local  __resultvar=$1
  elasticIpName=$2

  address=$(aws ec2 describe-addresses --query "Addresses[].PublicIp" --filter "Name=tag:Name,Values=$elasticIpName" --output text)
  checkForAWSError $?

 eval $__resultvar="$address"

}



# find a key pair by name
# empty if not found, else returns KeyFingerprint
function lookForKeyPair() {
  local  __resultvar=$1
  lookingFor=$2

  echo "Looking for key pair named: $lookingFor"
  fingerprint=$(aws ec2 describe-key-pairs --filters "Name=key-name,Values=$lookingFor" --query "KeyPairs[].KeyFingerprint" --output text)
  checkForAWSError $?

  eval $__resultvar="$fingerprint"
}

# creates key pair by name
# returns key fingerprint
function createKeyPair() {
  local  __resultvar=$1
  keyPairName=$2

  # create key pair, writes private key to file
  aws ec2 create-key-pair --key-name $keyPairName --query KeyMaterial --output text > "${keyPairName}.pem"
  checkForAWSError $?

  # get fingerprint for return
  kpPrint=$(aws ec2 describe-key-pairs --key-names $keyPairName --query KeyPairs[].KeyFingerprint --output text)

  eval $__resultvar="$kpPrint"
}

# hard stop if key material file not found (.pem)
function validateKeyMaterialFromFile() {
  keyPairName=$1

  # file should exist
  if [ ! -f "${keyPairName}.pem" ]; then
    echo "FATAL ERROR could not find local key pair file: ${keyPairName}.pem.  Delete EC2 keypair named '${keyPairName}' and allow the key pair secret to be redownloaded locally."
    exit 3
  fi
}



# given an security group name, find ID
# empty if not found
function lookForSecurityGroup() {
  local  __resultvar=$1
  vpcId=$2
  lookingFor=$3

  echo "Looking for security group named: $lookingFor"
  groupId=$(aws ec2 describe-security-groups --filters "Name=description,Values=$lookingFor" "Name=vpc-id,Values=$vpcId" --query "SecurityGroups[].GroupId" --output text)
  checkForAWSError $?

  eval $__resultvar="$groupId"
}

# creates elastic IP tagged with name
# returns ID of security group created
function createSecurityGroup() {
  local  __resultvar=$1
  vpcId=$2
  groupName=$3

  # create subnet
  groupId=$(aws ec2 create-security-group --group-name "$groupName" --description "$groupName" --vpc-id $vpcId --query GroupId --output text)
  checkForAWSError $?

  # tag with name
  aws ec2 create-tags --resources $groupId --tags "Key=Name,Value=$groupName"
  checkForAWSError $?

 eval $__resultvar="$groupId"
}



# updates security group ingress rules
function updateSecurityGroupRules() {
  vpcId=$1
  groupId=$2
  groupIdOther=$3
  rulesName=$4

  # assign specific array
  tmp=$rulesName[@]
  ingressRules=( "${!tmp}" )
  #if [ "$rulesName" == "bosh" ]; then
  #  ingressRules=( "${BOSH_INGRESS_RULES[@]}" )
  #elif [ "$rulesName" == "jumpbox" ]; then
  #  ingressRules=( "${DMZ_INGRESS_RULES[@]}" )
  #fi

  # for restoring later
  OLDIFS=$IFS

  # get hash of all rules already defined in security group
  declare -A rulesMap
  existingRules=$(aws ec2 describe-security-groups --group-id $groupId --query "SecurityGroups[].IpPermissions[].[IpRanges,UserIdGroupPairs][][].Description" --output text)
  echo "ALL existing rules: $existingRules"

  # add existing rules to map
  IFS=$'\t'
  for existingRule in $existingRules; do
    #echo "adding existing rule '$existingRule' to map"
    rulesMap[$existingRule]=$existingRule
  done 


  # go through each rule we have predefined
  IFS='
'
  for rule in ${ingressRules[@]}; do

    # split rule into fields
    OLDIFS=$IFS
    IFS=',' read -r -a field <<< "$rule"
    IFS=$OLDIFS

    # name the fields to make it easier to work with
    rdesc=${field[0]}
    rproto=${field[1]}
    rport1=${field[2]}
    rport2=${field[3]}
    rsource=${field[4]}

    if [ -z  "${rulesMap[$rdesc]}" ]; then
      echo "Need to create rule '$rdesc' with source '$rsource' because it does not exist on security group"
      # new rule takes this form
      if [[ "$rsource" =~ '**groupId' ]]; then
        # special marker for groupId gets replaced here
        #echo "rsource orig: $rsource"
        rsource=${rsource//**groupIdSelf**/$groupId}
        rsource=${rsource//**groupIdOther**/$groupIdOther}
        #echo "rsource trans: $rsource"

        # if ICMP then just -1 to signify all ports
        rangeStr="${rport1}-${rport2}"
        if [ "icmp" == "$rproto" ]; then 
          rangeStr="${rport1}"
        fi

        ruleString="IpProtocol=$rproto,FromPort=$rport1,ToPort=$rport2,UserIdGroupPairs=[{Description=\"$rdesc\",GroupId=\"$rsource\"}]"
        aws ec2 authorize-security-group-ingress --group-id $groupId --output text --ip-permissions $ruleString

        if [[ $? -eq 0 ]]; then 
          echo "RULE RESULT sg: OK"
        else
          echo "WARNING: Attempt to update sg ingress rule failed"
        fi

      else

        ruleString="IpProtocol=$rproto,FromPort=$rport1,ToPort=$rport2,IpRanges=[{CidrIp=$rsource,Description=\"$rdesc\"}]"
        aws ec2 authorize-security-group-ingress --group-id $groupId --output text --ip-permissions $ruleString

        if [[ $? -eq 0 ]]; then 
          echo "RULE RESULT: OK"
        else
          echo "WARNING: Attempt to update ingress rule failed"
        fi

      fi

    else
      echo "Rule '$rdesc' already exists on security group, skipping"
    fi

  done

  # restore original IFS 
  IFS=$OLDIFS
}

# show ingress rule array for private subnet
function showIngressRuleArray() {
  rulesName=$1

  # assign specific rules array
  tmp=$rulesName[@]
  ingressRules=( "${!tmp}" )

  OLDIFS=$IFS
  IFS='
'
  for rule in ${ingressRules[@]}; do

    # split rule into fields
    IFS=',' read -r -a field <<< "$rule"
    rdesc=${field[0]}
    rproto=${field[1]}
    rport1=${field[2]}
    rport2=${field[3]}
    # 4th field and any after
    rsource=${field[4]}
 
    #echo "PREDEFINED RULE: $rdesc - $rproto - $rport1 - $rport2 - $rsource"
  done

  IFS=$OLDIFS
}


# gets internet gateway given tagged name
function lookForInternetGateway() {
  local  __resultvar=$1
  vpcId=$2
  internetGatewayName=$3

  gwId=$(aws ec2 describe-internet-gateways --filters "Name=tag:Name,Values=$internetGatewayName, Name=attachment.vpc-id,Values=$vpcId" --query InternetGateways[].InternetGatewayId --output text)
  checkForAWSError $?

 eval $__resultvar="$gwId"
}

# creates internet gateway used for private subnets to reach internet
# then attaches to vpc
# returns ID of internet gateway created
function createInternetGateway() {
  local  __resultvar=$1
  vpcId=$2
  vpcName=$3

  # create internet gateway
  gwId=$(aws ec2 create-internet-gateway --query InternetGateway.InternetGatewayId --output text)
  checkForAWSError $?

  # tag with name
  aws ec2 create-tags --resources $gwId --tags "Key=Name,Value=$vpcName"
  checkForAWSError $?

  # attach to vpc
  aws ec2 attach-internet-gateway --internet-gateway-id $gwId --vpc-id $vpcId
  checkForAWSError $?

 eval $__resultvar="$gwId"
}



# gets NAT gateway given tagged name
function lookForNATGateway() {
  local  __resultvar=$1
  subnetId=$2
  natGatewayName=$3

  natId=$(aws ec2 describe-nat-gateways --filter "Name=tag:Name,Values=$natGatewayName,Name=subnet-id,Values=$subnetId,Name=state,Values=available" --query NatGateways[].NatGatewayId --output text)
  checkForAWSError $?

 eval $__resultvar="$natId"
}

# creates NAT gateway used for public subnets to reach internet
# returns ID of NAT gateway created
function createNATGateway() {
  local  __resultvar=$1
  natGatewayName=$2
  subnetId=$3
  elasticId=$4

  # create NAT gateway
  natId=$(aws ec2 create-nat-gateway --subnet-id $subnetId --allocation-id $elasticId --query NatGateway.NatGatewayId --output text)
  checkForAWSError $?

  # tag with name
  aws ec2 create-tags --resources $natId --tags "Key=Name,Value=${natGatewayName}"
  checkForAWSError $?

 eval $__resultvar="$natId"
}



# gets routing table given tagged name
function lookForRoutingTable() {
  local  __resultvar=$1
  vpcId=$2
  routingName=$3

  routeId=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpcId,Name=route.state,Values=active,Name=tag:Name,Values=$routingName" --query RouteTables[].RouteTableId --output text)
  checkForAWSError $?

 eval $__resultvar="$routeId"
}

# not creating default route to NAT
#  createRoutingTable natroutingId $vpcId $subnetBoshName $natgwId $subnetBoshId

# creates route table, associates route
# returns ID of route table created
function createRoutingTable() {
  local  __resultvar=$1
  vpcId=$2
  routingName=$3
  gatewayId=$4
  subnetId=$5

  # create routing table
  routeId=$(aws ec2 create-route-table --vpc-id $vpcId --query RouteTable.RouteTableId --output text)
  checkForAWSError $?

  # tag with name
  aws ec2 create-tags --resources $routeId --tags "Key=Name,Value=$routingName"
  checkForAWSError $?

  # create default route that points all traffic to gateway
  echo aws ec2 create-route --route-table-id $routeId --destination-cidr-block 0.0.0.0/0 --gateway-id $gatewayId
  retVal=$(aws ec2 create-route --route-table-id $routeId --destination-cidr-block 0.0.0.0/0 --gateway-id $gatewayId)

  # associate routing table to subnet
  retVal=$(aws ec2 associate-route-table --route-table-id $routeId --subnet-id $subnetId --output text)

 eval $__resultvar="$routeId"
}



# gets latest instance image by owner, name (which can be wildcarded)
function lookForLatestImage() {
  local  __resultvar=$1
  ownerId=$2
  imageName=$3

  imageId=$(aws ec2 describe-images --owners $ownerId --filters "Name=name,Values=$imageName" "Name=state,Values=available" --query "reverse(sort_by(Images, &CreationDate)[].ImageId)[0]" --output text)
  checkForAWSError $?

 eval $__resultvar="$imageId"
}


# gets instance given tagged name
function lookForRunningInstance() {
  local  __resultvar=$1
  instanceName=$2

  # look for running instance by name
  instanceId=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=$instanceName" "Name=instance-state-name,Values=running" --query Reservations[].Instances[].InstanceId --output text)
  checkForAWSError $?

 eval $__resultvar="$instanceId"
}

# waits for instance to be in requested state
function waitForState() {
  # instance|instancestatus|natgw
  entityType=$1
  entityId=$2
  requestedState=$3
  pollingSeconds=$4
  maxCount=$5

  echo "Going to wait for state '$requestedState' on entity of type $entityType"
  count=0
  while [ 1 -eq 1 ]; do

    # only poll a certain number of times before erroring
    count=$((count+1))
    #echo "Poll count: $count"
    if [ $count -gt $maxCount ]; then
      echo "POLL TIMEOUT - $entityId never reached state $requestedState"
      exit 99
    fi

    case "$entityType" in

    "instance") 
      state=$(aws ec2 describe-instances --instance-ids $entityId --query Reservations[].Instances[].State.Name --output text)
      checkForAWSError $?
      ;;

    "instancestatus") 
      state=$(aws ec2 describe-instance-status --instance-ids $entityId --query InstanceStatuses[].SystemStatus.Status --output text)
      checkForAWSError $?
      ;;

    "natgw")
      state=$(aws ec2 describe-nat-gateways --nat-gateway-ids $entityId --query NatGateways[].State --output text)
      checkForAWSError $?
      ;;

    *)
      echo "UNRECOGNIZED ENTITY TYPE $entityType, cannot look for state"
      return
      ;;

    esac
    
    if [[ "$state" == "$requestedState" ]]; then
     echo "State of $entityId is now $state, continuing"
     return 0
    else
      echo "State of $entityId is $state, going to poll again in $pollingSeconds..."
      sleep $pollingSeconds
    fi
  done
}

# creates instance
# returns ID of instance created
# look at /var/log/cloud-init-output for any errors in startup script
function createInstance() {
  local  __resultvar=$1
  instanceName=$2
  instanceType=$3
  xenialId=$4
  subnetDMZId=$5
  securityGroupDMZId=$6
  keypairName=$7
  startupScript=$8

  userData=""
  # if startup script name provided, then populate switch
  if [ ! -z $startupScript ]; then
    userData="file://$startupScript"
  fi
  echo "userData is $userData"

  # create instance
  instanceId=$(aws ec2 run-instances --image-id $xenialId --subnet-id $subnetDMZId --user-data $userData --security-group-ids $securityGroupDMZId --count 1 --instance-type $instanceType --key-name $keypairName --query Instances[0].InstanceId --output text)
  checkForAWSError $?

  # tag with name
  aws ec2 create-tags --resources $instanceId --tags "Key=Name,Value=$instanceName"
  checkForAWSError $?

 eval $__resultvar="$instanceId"
}


# finds if instance has elastic IP attached
function lookForElasticIPOnInstance() {
  local  __resultvar=$1
  instanceId=$2

  # look for running instance by name
  publicIP=$(aws ec2 describe-instances --instance-ids $instanceId --query Reservations[].Instances[].NetworkInterfaces[].PrivateIpAddresses[].Association.PublicIp --output text)
  checkForAWSError $?

 eval $__resultvar="$publicIP"
}

# associate instance with ElasticIP (pass in elastic allocation id, not IP address)
function associateElasticIPWithInstance() {
  instanceId=$1
  allocationId=$2

  associationId=$(aws ec2 associate-address --instance-id $instanceId --allocation-id $allocationId --output text)
  checkForAWSError $?

}

