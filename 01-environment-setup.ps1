Import-Module ".\environment-automation"

$InformationPreference = "Continue"

$subs = Get-AzSubscription | Select-Object -ExpandProperty Name
if($subs.GetType().IsArray -and $subs.length -gt 1){
        $subOptions = [System.Collections.ArrayList]::new()
        for($subIdx=0; $subIdx -lt $subs.length; $subIdx++){
                $opt = New-Object System.Management.Automation.Host.ChoiceDescription "$($subs[$subIdx])", "Selects the $($subs[$subIdx]) subscription."   
                $subOptions.Add($opt)
        }
        $selectedSubIdx = $host.ui.PromptForChoice('Introduzca la suscripción de Azure','Copia y pega el nombre de la suscripción Azure.', $subOptions.ToArray(),0)
        $selectedSubName = $subs[$selectedSubIdx]
        Write-Information "Seleccionando la suscripción $selectedSubName"
        Select-AzSubscription -SubscriptionName $selectedSubName
}

$userName = ((az ad signed-in-user show -o json) | ConvertFrom-JSON).UserPrincipalName
$resourceGroupName = Read-Host -Prompt "Introduce el nombre del grupo de recursos que tiene el Workspace de Azure Synapse Analytics"
$sqlPassword = Read-Host -Prompt "Introduce la contraseña del administrador SQL usada al crear el servicio Azure Synapse Analytics" -AsSecureString
$sqlPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($sqlPassword))
$uniqueId = Read-Host -Prompt "Introduce el sufijo elegido en el despliegue"

$subscriptionId = (Get-AzContext).Subscription.Id
$global:logindomain = (Get-AzContext).Tenant.Id

$templatesPath = ".\templates"
$datasetsPath = ".\datasets"
$sqlScriptsPath = ".\sql"
$workspaceName = "asirsynapse$($uniqueId)"
$dataLakeAccountName = "asirdatalake$($uniqueId)"
$blobStorageAccountName = "asiralmacenamiento$($uniqueId)"
$keyVaultName = "asirclaves$($uniqueId)"
$keyVaultSQLUserSecretName = "SQL-USER-ASA"
$sqlPoolName = "SQLPool01"
$sqlUserName = "sqladministrador"
$integrationRuntimeName = "AzureIntegrationRuntime01"
$sparkPoolName = "SparkPool01"
$amlWorkspaceName = "asirMachineLearning$($uniqueId)"

$global:synapseToken = ""
$global:synapseSQLToken = ""
$global:managementToken = ""

$global:tokenTimes = [ordered]@{
        Synapse = (Get-Date -Year 1)
        SynapseSQL = (Get-Date -Year 1)
        Management = (Get-Date -Year 1)
}

Get-AzResourceGroup -Name $resourceGroupName -ErrorVariable rgNotPresent -ErrorAction SilentlyContinue

if ($rgNotPresent)
{
    throw "El grupo de recursos $($resourceGroupName) no existe en esa suscripción."
}

Write-Information "Asignando la propiedad en el Workspace de Synapse"
Assign-SynapseRole -WorkspaceName $workspaceName -RoleId "6e4bf58a-b8e1-4cc3-bbf9-d73143322b78" -PrincipalId "37548b2e-e5ab-4d2b-b0da-4d812f56c30e"  # Workspace Admin
Assign-SynapseRole -WorkspaceName $workspaceName -RoleId "7af0c69a-a548-47d6-aea3-d00e69bd83aa" -PrincipalId "37548b2e-e5ab-4d2b-b0da-4d812f56c30e"  # SQL Admin
Assign-SynapseRole -WorkspaceName $workspaceName -RoleId "c3a6d2f1-a26f-4810-9b0f-591308d5cbf1" -PrincipalId "37548b2e-e5ab-4d2b-b0da-4d812f56c30e"  # Apache Spark Admin

#añadir permisos al datalake
$id = (Get-AzADServicePrincipal -DisplayName $workspacename).id
New-AzRoleAssignment -Objectid $id -RoleDefinitionName "Storage Blob Data Owner" -Scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$dataLakeAccountName" -ErrorAction SilentlyContinue;
New-AzRoleAssignment -SignInName $username -RoleDefinitionName "Storage Blob Data Owner" -Scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$dataLakeAccountName" -ErrorAction SilentlyContinue;

Write-Information "Configurando política de almacén de claves"
Set-AzKeyVaultAccessPolicy -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -UserPrincipalName $userName -PermissionsToSecrets set,delete,get,list

$ws = Get-Workspace $SubscriptionId $ResourceGroupName $WorkspaceName;
$upid = $ws.identity.principalid
Set-AzKeyVaultAccessPolicy -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -ObjectId $upid -PermissionsToSecrets set,delete,get,list

Write-Information "Creando secreto para SQL-USER-ASA en el almacén de claves"
$secretValue = ConvertTo-SecureString $sqlPassword -AsPlainText -Force
$secret = Set-AzKeyVaultSecret -VaultName $keyVaultName -Name $keyVaultSQLUserSecretName -SecretValue $secretValue

Write-Information "Creando secreto para el servicio linkado en el almacén de claves $($keyVaultName)"

$result = Create-KeyVaultLinkedService -TemplatesPath $templatesPath -WorkspaceName $workspaceName -Name $keyVaultName
Wait-ForOperation -WorkspaceName $workspaceName -OperationId $result.operationId

Write-Information "Creando el Runtime de integración $($integrationRuntimeName)"

$result = Create-IntegrationRuntime -TemplatesPath $templatesPath -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -Name $integrationRuntimeName -CoreCount 16 -TimeToLive 60
Wait-ForOperation -WorkspaceName $workspaceName -OperationId $result.operationId

Write-Information "Creando servicio linkado con el almacén DataLake $($dataLakeAccountName)"

$dataLakeAccountKey = List-StorageAccountKeys -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -Name $dataLakeAccountName
$result = Create-DataLakeLinkedService -TemplatesPath $templatesPath -WorkspaceName $workspaceName -Name $dataLakeAccountName  -Key $dataLakeAccountKey
Wait-ForOperation -WorkspaceName $workspaceName -OperationId $result.operationId

Write-Information "Creando servicio linkado con el almacén Blob $($blobStorageAccountName)"

$blobStorageAccountKey = List-StorageAccountKeys -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -Name $blobStorageAccountName
$result = Create-BlobStorageLinkedService -TemplatesPath $templatesPath -WorkspaceName $workspaceName -Name $blobStorageAccountName  -Key $blobStorageAccountKey
Wait-ForOperation -WorkspaceName $workspaceName -OperationId $result.operationId

Write-Information "Iniciando la cola SQL $($sqlPoolName) si se necesita... esto puede tardar."

$result = Get-SQLPool -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -SQLPoolName $sqlPoolName
if ($result.properties.status -ne "Online") {
    Control-SQLPool -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -SQLPoolName $sqlPoolName -Action resume
    Wait-ForSQLPool -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -SQLPoolName $sqlPoolName -TargetStatus Online
}

Write-Information "Setup $($sqlPoolName)"

$params = @{
        "PASSWORD" = $sqlPassword
        "DATALAKESTORAGEKEY" = $dataLakeAccountKey
        "DATALAKESTORAGEACCOUNTNAME" = $dataLakeAccountName
}


try
{
    $result = Execute-SQLScriptFile-SqlCmd -SQLScriptsPath $sqlScriptsPath -WorkspaceName $workspaceName -SQLPoolName $sqlPoolName -SQLUserName $sqlUserName -SQLPassword $sqlPassword -FileName "01_sqlpool01_mcw" -Parameters $params
}
catch 
{
    write-host $_.exception
}


$result

Write-Information "Creando linked service a la cola SQL $($sqlPoolName) con el usuario sqladministrador"

$linkedServiceName = $sqlPoolName.ToLower()
$result = Create-SQLPoolKeyVaultLinkedService -TemplatesPath $templatesPath -WorkspaceName $workspaceName -Name $linkedServiceName -DatabaseName $sqlPoolName `
                 -UserName "sqladministrador" -KeyVaultLinkedServiceName $keyVaultName -SecretName $keyVaultSQLUserSecretName
Wait-ForOperation -WorkspaceName $workspaceName -OperationId $result.operationId


Write-Information "Creando conjuntos de datos..."

$datasets = @{
        asamcw_product_asa = $sqlPoolName.ToLower()
        asamcw_product_csv = $dataLakeAccountName
}

foreach ($dataset in $datasets.Keys) 
{
        Write-Information "Creando DataSet $($dataset)"
        $result = Create-Dataset -DatasetsPath $datasetsPath -WorkspaceName $workspaceName -Name $dataset -LinkedServiceName $datasets[$dataset]
        Wait-ForOperation -WorkspaceName $workspaceName -OperationId $result.operationId
}


$publicDataUrl = "https://solliancepublicdata.blob.core.windows.net/"
$dataLakeStorageUrl = "https://"+ $dataLakeAccountName + ".dfs.core.windows.net/"
$dataLakeStorageBlobUrl = "https://"+ $dataLakeAccountName + ".blob.core.windows.net/"
$dataLakeStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -AccountName $dataLakeAccountName)[0].Value
$dataLakeContext = New-AzureStorageContext -StorageAccountName $dataLakeAccountName -StorageAccountKey $dataLakeStorageAccountKey
$destinationSasKey = New-AzureStorageContainerSASToken -Container "wwi-02" -Context $dataLakeContext -Permission rwdl

Write-Information "Copiando archivos con datos de ejemplo..."
$singleFiles = @{
        parquet_query_file = "wwi-02/sale-small/Year=2010/Quarter=Q4/Month=12/Day=20101231/sale-small-20101231-snappy.parquet"
        customer_info = "wwi-02/customer-info/customerinfo.csv"
        campaign_analytics = "wwi-02/campaign-analytics/campaignanalytics.csv"
        products = "wwi-02/data-generators/generator-product/generator-product.csv"
        model = "wwi-02/ml/onnx-hex/product_seasonality_classifier.onnx.hex"
}

foreach ($singleFile in $singleFiles.Keys) {
        $source = $publicDataUrl + $singleFiles[$singleFile]
        $destination = $dataLakeStorageBlobUrl + $singleFiles[$singleFile] + $destinationSasKey
        Write-Information "Copying file $($source) to $($destination)"
        azcopy copy $source $destination 
}

Write-Information "Copiando datos de ventas de ejemplo de datos públicos..."
$dataDirectories = @{
        data2018 = "wwi-02/sale-small,wwi-02/sale-small/Year=2018/"
        data2019 = "wwi-02/sale-small,wwi-02/sale-small/Year=2019/"
}

foreach ($dataDirectory in $dataDirectories.Keys) {
        $vals = $dataDirectories[$dataDirectory].tostring().split(",");
        $source = $publicDataUrl + $vals[1];
        $path = $vals[0];

        $destination = $dataLakeStorageBlobUrl + $path + $destinationSasKey
        Write-Information "Copiando directorio $($source) a $($destination)"
        azcopy copy $source $destination --recursive=true
}

Write-Information "Copiando datos de ejemplo JSON del repositorio..."
$rawData = "./rawdata/json-data"
$destination = $dataLakeStorageUrl +"wwi-02/product-json" + $destinationSasKey
azcopy copy $rawData $destination --recursive

Write-Information "Configurando las tablas de Machine Learning en la cola SQL"
$params = @{
    "PASSWORD" = $sqlPassword
    "DATALAKESTORAGEKEY" = $dataLakeStorageAccountKey
    "DATALAKESTORAGEACCOUNTNAME" = $dataLakeAccountName
}

try
{
    Execute-SQLScriptFile-SqlCmd -SQLScriptsPath $sqlScriptsPath -WorkspaceName $workspaceName -SQLPoolName $sqlPoolName -SQLUserName $sqlUserName -SQLPassword $sqlPassword -FileName "02_sqlpool01_ml" -Parameters $params
}
catch 
{
    write-host $_.exception
}

Write-Information "Validando el entorno..."

$sqlConnectionString = "Server=tcp:$($workspaceName).sql.azuresynapse.net,1433;Initial Catalog=$($sqlPoolName);Persist Security Info=False;User ID=$($sqlUserName);Password=$($sqlPassword);MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
$validEnvironment = $true


Write-Information "Verificando la existencia del esquema wwi_mcw con datos de ejemplo..."
$schemaQuery = "select count(name) as Count from sys.schemas where name='wwi_mcw'"
$result = (Invoke-SqlCmd -Query $schemaQuery -ConnectionString $sqlConnectionString) | Select-Object -ExpandProperty Count
if ($result -eq 1){Write-Host 'Schema wwi_mcw verified'}else{Write-Host 'Schema wwi_mcw not found' -ForegroundColor Red;$validEnvironment = $false}

Write-Information "Verificando la existencia de las tablas en la cola SQL..."
$sqlTables = 'Product'
foreach($table in $sqlTables)
{
        $tblQuery = "select count(name) as Count from sys.tables where name = '$($table)' and SCHEMA_NAME(schema_id) = 'wwi_mcw'"
        $result = (Invoke-SqlCmd -Query $tblQuery -ConnectionString $sqlConnectionString) | Select-Object -ExpandProperty Count
        if ($result -eq 1){       
        	Write-Host "Table $($table) verificada"
        }
        else {
        	Write-Host "Tabla $($table) no encontrada" -ForegroundColor Red
        	$validEnvironment = $false
        }
}

$scopedCredentialQuery = "select count(name) as Count from sys.database_scoped_credentials where name='CredencialBBDD'"
$result = (Invoke-SqlCmd -Query $scopedCredentialQuery -ConnectionString $sqlConnectionString) | Select-Object -ExpandProperty Count
if ($result -eq 1){Write-Host 'Credenciales de Base de Datos verificadas.'}else{Write-Host 'Credenciales de Base de Datos no encontradas.' -ForegroundColor Red;$validEnvironment = $false}

Write-Information "Verifying the existence of the SQL External Data Source (Storage)..."
$extDataSourceQuery = "select count(name) as Count from sys.external_data_sources where name='DataLakeExterno'"
$result = (Invoke-SqlCmd -Query $extDataSourceQuery -ConnectionString $sqlConnectionString) | Select-Object -ExpandProperty Count
if ($result -eq 1){Write-Host 'External data source DataLakeExterno verified'}else{Write-Host 'External data source DataLakeExterno not found' -ForegroundColor Red;$validEnvironment = $false}


Write-Information "Verifying the existence of the SQL CSV external file format..."
$fileFormatQuery = "select count(name) as Count from sys.external_file_formats where name='csv'"
$result = (Invoke-SqlCmd -Query $fileFormatQuery -ConnectionString $sqlConnectionString) | Select-Object -ExpandProperty Count
if ($result -eq 1){Write-Host 'File Format csv verified'}else{Write-Host 'File format csv not found' -ForegroundColor Red;$validEnvironment = $false}

$storageFilesAndFolders = @{
        parquet_query_file = "wwi-02/sale-small/Year=2010/Quarter=Q4/Month=12/Day=20101231/sale-small-20101231-snappy.parquet"
        customer_info = "wwi-02/customer-info/customerinfo.csv"
        campaign_analytics = "wwi-02/campaign-analytics/campaignanalytics.csv"
        products = "wwi-02/data-generators/generator-product/generator-product.csv"
        model = "wwi-02/ml/onnx-hex/product_seasonality_classifier.onnx.hex"
        json1 = "wwi-02/product-json/json-data/product-1.json"
        json2 = "wwi-02/product-json/json-data/product-2.json"
        json3 = "wwi-02/product-json/json-data/product-3.json"
        json4 = "wwi-02/product-json/json-data/product-4.json"
        json5 = "wwi-02/product-json/json-data/product-5.json"
        ss2018 = "wwi-02/sale-small/Year=2018"
        ss2019 = "wwi-02/sale-small/Year=2019"
}

Write-Information "Verifying the data lake storage account and required files..."
$dataLakeAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $dataLakeAccountName

if ($dataLakeAccount -eq $null) {
        Write-Host "The datalake account $($dataLakeAccountName) was not found" -ForegroundColor Red
        $validEnvironment = $false
} else {
	foreach($storageFileOrFolder in $storageFilesAndFolders.Keys){	
		$dataLakeItem = Get-AzDataLakeGen2Item -Context $dataLakeAccount.Context -FileSystem $storageFilesAndFolders[$storageFileOrFolder].Split("/")[0] -Path $storageFilesAndFolders[$storageFileOrFolder].Replace($storageFilesAndFolders[$storageFileOrFolder].Split("/")[0] +"/","")
		if(!($dataLakeItem -eq $null)){
			Write-Host "Data Lake $($storageFilesAndFolders[$storageFileOrFolder]) has been verified"
		} else {
			Write-Host "Data Lake $($storageFilesAndFolders[$storageFileOrFolder]) not found" -ForegroundColor Red
        	        $validEnvironment = $false
		}
	}
}

$pathsAndCounts = @{
    "wwi-02/sale-small/Year=2018" = 365
    "wwi-02/sale-small/Year=2019" = 364
}

foreach($path in $pathsAndCounts.Keys){
	$fileCount = (Get-AzDataLakeGen2ChildItem -Context $dataLakeAccount.Context -FileSystem $path.Split("/")[0] -Path $path.Replace($path.Split("/")[0] +"/","") -Recurse | Where-Object {$_.Length -gt 0}).Count
	if($fileCount -eq $pathsAndCounts[$path]){
		Write-Host "$($path) file count verified at $($pathsAndCounts[$path])"
	} else {
                Write-Host "$($path) file count INCORRECT expected $($pathsAndCounts[$path]), actual $($fileCount)." -ForegroundColor Red
                $validEnvironment = $false
	}
}

$asaArtifacts = [ordered]@{

        "asamcw_product_csv" = "datasets"
        "asamcw_product_asa" = "datasets"
        "$($keyVaultName)" = "linkedServices"
        "$($dataLakeAccountName)" = "linkedServices"
        "$($blobStorageAccountName)" = "linkedServices"
        "$($sqlPoolName)" = "linkedServices"
}

foreach ($asaArtifactName in $asaArtifacts.Keys) {
        try {
                Write-Information "Checking $($asaArtifactName) in $($asaArtifacts[$asaArtifactName])"
                $result = Get-ASAObject -WorkspaceName $workspaceName -Category $asaArtifacts[$asaArtifactName] -Name $asaArtifactName
                Write-Host "$($asaArtifactName) verified in Synapse Workspace $($asaArtifacts[$asaArtifactName])"
        }
        catch {
                Write-Host "$($asaArtifactName) verified in Synapse Workspace $($asaArtifacts[$asaArtifactName])" -ForegroundColor Red
                $validEnvironment = $false
        }
}

if($validEnvironment = $true){
        Write-Host "Environment validation has succeeded." -ForegroundColor Green
} else {
        Write-Host "Environment validation has failed. Please check the above output for Red messages." -ForegroundColor Red
}
