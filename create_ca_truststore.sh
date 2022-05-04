#!/bin/bash
bash --version

resourcesRoot="./sertifikatvalidator-server/src/main/resources"
echo $resourcesRoot

#LEGG TIL NYE CA SERTIFIKATER HER PÅ FORMAT "[ALIAS]|[STI_TIL_CERT]"
alias_ca_map_dev=(
    #BUYPASS CA SEID 2.0 TEST
    "buypass_test4_ca2_ht_root|$resourcesRoot/seid2ca/buypass/test/BPCl3RootCaG2HT.cer"
    "buypass_test4_ca2_ht_p|$resourcesRoot/seid2ca/buypass/test/BPCl3CaG2HTPS.cer"
    "buypass_test4_ca2_ht_b|$resourcesRoot/seid2ca/buypass/test/BPCl3CaG2HTBS.cer"
    "buypass_test4_ca2_st_root|$resourcesRoot/seid2ca/buypass/test/BPCl3RootCaG2ST.cer"
    "buypass_test4_ca2_st_b|$resourcesRoot/seid2ca/buypass/test/BPCl3CaG2STBS.cer"

    #COMMFIDES CA SEID 2.0 TEST
    "commfides_g3_test_ca_lp|$resourcesRoot/seid2ca/commfides/test/CommfidesLegalPersonCA-G3-TEST.cer"
    "commfides_g3_test_ca_np|$resourcesRoot/seid2ca/commfides/test/CommfidesNaturalPersonCA-G3-TEST.cer"
    "commfides_g3_test_ca_misc|$resourcesRoot/seid2ca/commfides/test/CommfidesMISCCA-G3-TEST.cer"
    "commfides_g3_test_ca_root|$resourcesRoot/seid2ca/commfides/test/CommfidesRootCA-G3-TEST.cer"
)

alias_ca_map_prod=(
    #BUYPASS CA SEID 2.0 PROD
    "buypass_prod_ca2_ht_root|$resourcesRoot/seid2ca/buypass/prod/BPCl3RootCaG2HT.cer"
    "buypass_prod_ca2_ht_p|$resourcesRoot/seid2ca/buypass/prod/BPCl3CaG2HTPS.cer"
    "buypass_prod_ca2_ht_b|$resourcesRoot/seid2ca/buypass/prod/BPCl3CaG2HTBS.cer"
    "buypass_prod_ca2_st_root|$resourcesRoot/seid2ca/buypass/prod/BPCl3RootCaG2ST.cer"
    "buypass_prod_ca2_st_b|$resourcesRoot/seid2ca/buypass/prod/BPCl3CaG2STBS.cer"

    #COMMFIDES CA SEID 2.0 PROD
    "commfides_g3_prod_ca_lp|$resourcesRoot/seid2ca/commfides/prod/CommfidesLegalPersonCA-G3.cer"
    "commfides_g3_prod_ca_np|$resourcesRoot/seid2ca/commfides/prod/CommfidesNaturalPersonCA-G3.cer"
    "commfides_g3_prod_ca_misc|$resourcesRoot/seid2ca/commfides/prod/CommfidesMISCCA-G3.cer"
    "commfides_g3_prod_ca_root|$resourcesRoot/seid2ca/commfides/prod/CommfidesRootCA-G3.cer"
)



truststoreFileName="truststore.jks"
base64FileName="truststore_base64"
echo $truststoreFileName
truststoreFileDev="$resourcesRoot/dev_$truststoreFileName"
base64FileDev="$resourcesRoot/dev_$base64FileName"
echo $truststoreFileDev
truststoreFileProd="$resourcesRoot/prod_$truststoreFileName"
base64FileProd="$resourcesRoot/prod_$base64FileName"
echo $truststoreFileProd

echo "Enter truststore password: "
read -s truststorePass
#echo "Add production certs to dev truststore [yes]?"
#read addProductionCertsToDevStore

#TEST/DEV TRUSTSTORE
echo ""
echo "----------CREATING/UPDATING DEV TRUSTSTORE----------"
for index in "${alias_ca_map_dev[@]}"
  do
    alias="${index%%|*}"
    cert="${index##*|}"
    echo "Trying to add alias with cert from path to TEST truststore"
    echo "...$alias"
    echo "...$cert"
    keytool -import -alias $alias -file $cert -keystore $truststoreFileDev -storepass $truststorePass -storetype jks -noprompt
  done

keytool -list -keystore $truststoreFileDev -storepass $truststorePass
base64 -i $truststoreFileDev -o $base64FileDev
echo "Wrote JKS to base64 file at $base64FileDev"
echo "----------CREATING/UPDATING DEV TRUSTSTORE FINISHED, SEE $truststoreFileDev----------"
echo ""


#PROD TRUSTSTORE
echo ""
echo "----------CREATING/UPDATING PROD TRUSTSTORE----------"
for index in "${alias_ca_map_prod[@]}"
  do
    alias="${index%%|*}"
    cert="${index##*|}"
    echo "Trying to add alias with cert from path to PROD truststore"
    echo "...$alias"
    echo "...$cert"
    keytool -import -alias $alias -file $cert -keystore $truststoreFileProd -storepass $truststorePass -storetype jks -noprompt
    #Add prod certs to dev store? comment in line under
    #keytool -import -alias $alias -file $cert -keystore $truststoreFileDev -storepass $truststorePass -storetype jks -noprompt
  done

keytool -list -keystore $truststoreFileProd -storepass $truststorePass
base64 -i $truststoreFileProd -o $base64FileProd
echo "Wrote JKS to base64 file at $base64FileProd"
echo "----------CREATING/UPDATING PROD TRUSTSTORE FINISHED, SEE $truststoreFileProd----------"
echo ""