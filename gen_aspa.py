import copy
import os
import shlex
import subprocess

import pandas as pd
import random
import string



template_file_name = "aspa_template.conf"
project_path = os.path.dirname(os.path.abspath(__file__))

root_path = "/repository"
# opera_path = "/root/rpstir2/operate"
opera_path = project_path
host = "172.17.0.8"



class Cert:
    isRoot = False
    parentCert = root_path
    certName = ''
    cerPath = ''
    certPath = ''
    ASN = 123
    providerAS = []

    def __init__(self, isRoot, certName, parentCert, allAS):
        self.isRoot = isRoot
        self.certName = certName

        self.allAS = allAS
        if isRoot:
            self.parentCert = self.certName
        else:
            self.parentCert = parentCert

        # self.cerPath = '/'.join(self.parentCert.split('/')[:-1])
        #创建自己目录
        # cmd = "mkdir " + os.path.join(self.cerPath, self.certName.replace(".crt",""))
        # #os.mkdir(os.path.join(self.cerPath, self.certName.replace(".crt","")))

        # res = os.popen(cmd)

    def getCertName(self):
        return self.certName

    def getCertPath(self):
        return self.cerPath

    def genKey(self):
        '''
        openssl genrsa -out EE.key  2048
        '''
        keyPath = os.path.join(opera_path, self.certName.replace(".crt", ".key"))
        crtPath = os.path.join(root_path, self.certName)
        if os.path.exists(keyPath):
            # if os.path.exists(crtPath):
            #     cmd = "rm -rf " + crtPath
            #     status, output = subprocess.getstatusoutput(cmd)
            return keyPath
        cmd = "openssl genrsa -out " + keyPath + "  2048"
        # res = os.system(cmd)
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            print("keyPath gen faild",keyPath,"reason:",output)
        return keyPath

    def genSeqConf(self):
        '''
        [sia]
        1.3.6.1.5.5.7.48.5;URI=rsync://example.org/rpki/root/
        1.3.6.1.5.5.7.48.10;URI=rsync://example.org/rpki/root/root.mft
        [rfc3779_asns]
        AS.0=64496-64511
        AS.1=65536-65551
        '''
        templateConf =  os.path.join(opera_path, "reqopenssl.cnf")
        seqConfName =  os.path.join(opera_path, self.certName.replace(".crt", "_req.cnf"))
        with open(templateConf) as file:
            data = file.read().split('\n')
        #add provider
        providerConf = []
        for providerIndex in range(len(self.allAS)):
            providerConf.append('AS.' + str(self.allAS[providerIndex]) + '=' + str(self.allAS[providerIndex]))
        # add sia
        sia = "1.3.6.1.5.5.7.48.5;URI=rsync://" + host + os.path.join(root_path, self.certName.replace(".crt",""))
        confIndex = 0

        while confIndex < len(data):
            data[confIndex] = data[confIndex].strip()
            if data[confIndex].find('[rfc3779_asns]') != -1:
                data[confIndex+1:confIndex+2] = providerConf
            if data[confIndex].find('[sia]') != -1:
                data[confIndex + 1] = sia
            confIndex += 1

        with open(seqConfName, 'w') as file:
            for index in range(len(data)):
                file.write(data[index]+'\n')
        return seqConfName

    def genSeq(self, seqConfName, keyPath, ouName):
        '''
        openssl req -new \
        -key  eeserver.key \
        -subj "/C=CN/ST=BeiJing/L=BeiJing/O=ZDNS/OU=Lab/CN=ca.zdns.com/emailAddress=baozhuo@zdns.cn" \
        -config. / eeopenssl.cnf \
        -out  eeserver.csr
        '''
        csrPath = os.path.join(opera_path, self.certName.replace(".crt", ".csr"))
        if os.path.exists(csrPath):
            return csrPath
        cmd = "openssl req -new -key " + keyPath + \
              " -subj \"/C=CN/ST=BeiJing/L=BeiJing/O=ZDNS/OU=Lab" + ouName+ "/CN=ca.zdns.com/emailAddress=baozhuo@zdns.cn\""+\
              " -config " + seqConfName +\
              " -out " + csrPath
        # cmd = "openssl req -new -key /root/rpstir2/operate/riGQ2v4LS9Xclz1qaybhn6YOxeuCoVm5RZD7.key -modulus -noout -inform pem  -subj \"/C=CN/ST=BeiJing/L=BeiJing/O=ZDNS/OU=Lab/CN=ca.zdns.com/emailAddress=baozhuo@zdns.cn\" -config /root/rpstir2/operate/riGQ2v4LS9Xclz1qaybhn6YOxeuCoVm5RZD7_req.cnf -out /root/rpstir2/operate/riGQ2v4LS9Xclz1qaybhn6YOxeuCoVm5RZD7.csr"
        # args = shlex.split(cmd)
        # subprocess.Popen(args)

        #subprocess.call(cmd,shell=True)

        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            print("csrPath gen faild", csrPath, "reason:", output)
        return csrPath



    def caSign(self, childCsrPath, childCerPath):
        '''
        openssl ca -batch
            -in eeserver.csr \
            -cert root.pem
            -keyfile root.key \
            -extensions v3_req \
            -config ./reqopenssl.cnf
            -out ./eeserver.crt
        '''

        confName = os.path.join(opera_path, "openssl.cnf")
        pemPath = os.path.join(opera_path, self.certName.replace(".crt", ".pem"))
        cmd = "openssl x509 -in " +\
              os.path.join(root_path, self.certName) +\
              " -out "+ pemPath + " -outform PEM"
        res = os.popen(cmd)
        if os.path.exists(childCerPath):
            return childCerPath
        cmd  = "openssl ca -batch " +\
            " -in " + childCsrPath +\
            " -cert " + self.cerPath + self.certName.replace(".crt",".pem") +\
            " -keyfile " + opera_path + self.certName.replace(".crt","key") + \
            " -config " + confName + \
            " -extensions " + "v3_req" + \
            " -out " + childCerPath


        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            print("childCerPath gen faild", childCerPath, "reason:", output)
        return childCerPath

    def caSigned(self,parentCertPath, csrPath, cerPath, seqConfName):
        '''
        openssl ca -batch
            -in eeserver.csr \
            -cert root.pem
            -keyfile root.key \
            -extensions v3_req \
            -config ./reqopenssl.cnf
            -out ./eeserver.crt
        '''
        cerPath = os.path.join(root_path, self.certName)
        confName = os.path.join(opera_path, "openssl.cnf")
        cmd = "openssl x509 -in " + \
              os.path.join(root_path, parentCertPath) +\
              " -out "+ os.path.join(opera_path, parentCertPath.replace(".crt",".pem"))  + " -outform PEM"
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            print("caSigned gen faild", cmd, "reason:", output)
        if os.path.exists(cerPath):
            return cerPath

        cmd  = "openssl ca -batch " +\
            " -in " + csrPath +\
            " -cert " + os.path.join(opera_path, parentCertPath.replace(".crt",".pem"))  +\
            " -keyfile " + os.path.join(opera_path, parentCertPath.replace(".crt",".key"))  + \
            " -config " + seqConfName + \
            " -extensions " + "v3_req" + \
            " -out " + cerPath
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            print("cerPath gen faild", cerPath, "cmd",cmd, "reason:", output)

        return cerPath



    def selfSign(self, csrPath, keyPath):
        '''
          openssl x509 -req \
            -in server.csr \
            -out server.crt \
            -signkey server.key -days 3650
        '''
        seqConfName = os.path.join(opera_path, self.certName.replace(".crt", "_req.cnf"))
        cerPath = os.path.join(root_path, self.certName)
        if os.path.exists(cerPath):
            return cerPath
        cmd = "openssl x509 -req " + \
              " -in " + csrPath + \
              " -signkey " + keyPath + \
              " -extfile " + seqConfName +\
              " -extensions v3_req " + \
              " -out " + cerPath

        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            print("cerPath gen faild", cerPath, "reason:", output)
        return cerPath


class Aspa:
    EE = ''
    customerAs = 0
    providerASs = []
    def __init__(self,  customerAs, providerASs, aspaPath, ipType):

        self.customerAs = customerAs
        self.providerASs = providerASs
        self.fileName = aspaPath + "_" + ipType + ".aspa"
        self.IPType = ipType

    def genASN1Conf(self):
        templateConf = os.path.join(opera_path, "ASPA_DATA_Template.conf")
        seqConfName = os.path.join(opera_path, str(self.customerAs) + "_ASPA_DATA.conf")
        asn1FileName = os.path.join(opera_path, str(self.customerAs) + "_ASPA_DATA.asn")

        providerConf = []
        for providerIndex in range(len(self.providerASs)):
            providerConf.append('AS.' + str(providerIndex) + ' = ' + 'INTEGER:' + self.providerASs[providerIndex])

        with open(templateConf) as file:
            data = file.read().split('\n')
        index = 0

        while index < len(data):
            if data[index].find('customerASID = INTEGER:') != -1:
                data[index] = 'customerASID = INTEGER:' + str(self.customerAs)
            if data[index].find('[providerASs]') != -1:
                providerAs_index = index + 1
                # while data[providerAs_index] != '':
                #     providerAs_index += 1
                data[index + 1:index + 2] = providerConf
                # data[index:providerAs_index] = providerConf
            index += 1
        with open(seqConfName, 'w') as file:
            for index in range(len(data)):
                file.write(data[index]+'\n')

        '''
            openssl asn1parse -genconf xxxx.conf -out xxx.asn 
        '''
        cmd = "openssl asn1parse -genconf " + seqConfName + " -out " + asn1FileName
        status, output = subprocess.getstatusoutput(cmd)
        return asn1FileName



    def genCMS(self, asn1FileName, EEKeyPath, EECerPath):
        '''
          openssl cms -sign \
              -in ASPA_DATA_Template.der -inform DER -nodetach -binary  \
              -inkey eeserver.key  -signer eeserver.crt \
              -out result.aspa -outform DER \
              -econtent_type 1.2.840.113549.1.9.16.1.37
        '''
        aspaPath = os.path.join(root_path, self.fileName)
        # if os.path.exists(aspaPath):
        #     return aspaPath
        cmd = "openssl cms -sign  " +\
            " -in " + asn1FileName + " -inform DER -nodetach -binary  " +\
            " -inkey " + EEKeyPath +\
            " -signer " + EECerPath + \
            " -out " + aspaPath + " -outform DER " +\
            " -keyid  " + \
            " -econtent_type 1.2.840.113549.1.9.16.1.37"
        status, output = subprocess.getstatusoutput(cmd)
        if status !=0:
            print("genCMS faild: ",aspaPath ,"reason: ", output,"cmd:  ", cmd)
        return aspaPath




# #openssl x509 -text -in cacert.pem
# def get_aspa_data():
#     aspa_df = pd.read_csv(os.path.join(project_path, 'data/aspa_data_Template.csv'))
#     aspa_df['provider_as'] = aspa_df['provider_as'].apply(lambda x: x.split(','))
#     all_as = [i for j in list(aspa_df['provider_as']) for i in j]
#
#     return all_as

def get_aspa_data():
    isp_id_df = pd.read_csv(os.path.join(opera_path, 'data/isp_id.csv'))
    id_dict = {}
    id_dict.update(zip(isp_id_df.ISP.tolist(), isp_id_df.ISPID.tolist()))
    isp_id_dict = {}
    isp_id_dict.update(zip(isp_id_df.ISPID.tolist(), isp_id_df.ISP.tolist()))
    aspa_df = pd.read_csv(os.path.join(opera_path, 'data/aspa_data_Template.csv'))
    # aspa_df['provider_as'] = aspa_df['provider_as'].apply(lambda x: x.split(','))
    # all_as = [i for j in list(aspa_df['provider_as']) for i in j]A

    as_relation_map = {'Root': set([])}
    as_customer_map = {}
    as_provider_map = {}
    as_all_map = {}

    for index, row in aspa_df.iterrows():
        if not row['ParentISP'] == row['ISP']:
            try:
                as_relation_map[row['ParentISP']].add(row['ISP'])
            except:
                as_relation_map[row['ParentISP']] = set([row['ISP']])
        as_customer_map[row['ISP']] = row['customer_as']
        as_provider_map[row['ISP'] + "_" + str(row['ip_type'])] = row['provider_as'].split(',')
    all_path = []
    getChianPath(as_relation_map, as_customer_map, as_all_map, "Root", [], all_path)
    as_path_dir = []
    for i_index in range(len(all_path)):
        new_as_path_dir = []
        for j_index in range(len(all_path[i_index])):
            if not all_path[i_index][j_index] in id_dict:
                id_dict[all_path[i_index][j_index]] = ''.join(random.sample(string.ascii_letters + string.digits, 36))
            new_as_path_dir.append(id_dict[all_path[i_index][j_index]])
        as_path_dir.append(new_as_path_dir)


    # as_all_dir_map[id_dict[key]] = [as_customer_map[as_all_map[key][index]] for index in range(len(as_all_map[key]))  for key in as_all_map]

    as_all_dir_map = {id_dict[key]:[as_customer_map[as_all_map[key][index]] for index in range(len(as_all_map[key]))] for key in as_all_map}


    as_customer_dir_map = {id_dict[key]: as_customer_map[key] for key in as_customer_map}
    as_provider_dir_map = {id_dict[key[:-2]] + key[-2:]: as_provider_map[key] for key in as_provider_map}

    isp_id_df['ISP'] = list(id_dict.keys())
    isp_id_df['ISPID'] = list(id_dict.values())
    isp_id_df.to_csv(os.path.join(opera_path, 'data/isp_id.csv'), index=False)
    return as_path_dir, as_all_dir_map, as_customer_dir_map, as_provider_dir_map, isp_id_dict



def getChianPath(as_relation_map, as_customer_map, as_all_map, root, path, all_path):
    path.append(root)
    common_path = copy.copy(path)
    if not root in as_relation_map or len(as_relation_map['Root']) == 0:
        all_path.append(path)
        as_all_map[root] = [root]
        return
    else:
        sub_all_as = [root]
        len_as = len(path)
        for value in as_relation_map[root]:
            getChianPath(as_relation_map, as_customer_map, as_all_map, value, path, all_path)
            sub_all_as.extend(path[len_as:])
            path = copy.copy(common_path)
        as_all_map[root] = sub_all_as


# #返回所有的all_as
# def getChainAllAs():
#     return


def certSign(as_path, as_all_map, as_customer_map, as_provider_map, isp_id_dict):

    dirs = '/'.join(as_path)
    if not os.path.exists(os.path.join(root_path, dirs)):
        os.makedirs(os.path.join(root_path, dirs))
    if not os.path.exists(os.path.join(opera_path, dirs)):
        os.makedirs(os.path.join(opera_path, dirs))


    if len(as_path) == 1:
        # isRoot, certName, parentCert, allAS
        cert = Cert(isRoot=True, certName=dirs+'.crt', parentCert="", allAS=as_all_map[as_path[-1]])
        seqConfName = cert.genSeqConf()
        keyPath = cert.genKey()
        csrPath = cert.genSeq(seqConfName, keyPath, isp_id_dict[as_path[-1]])
        cerPath = cert.selfSign(csrPath, keyPath)


    else:
        #应该签发两个证书  一个是用于签发的证书  一个是用于EE证书
        parentDirs = '/'.join(as_path[:-1])
        cert = Cert(isRoot=False, certName=dirs + '.crt', parentCert= parentDirs + '.crt', allAS=as_all_map[as_path[-1]])
        seqConfName = cert.genSeqConf()
        keyPath = cert.genKey()
        csrPath = cert.genSeq(seqConfName, keyPath, isp_id_dict[as_path[-1]])
        cerPath = cert.caSigned(parentDirs + '.crt', csrPath, dirs + '.crt', seqConfName)


        for ee_type in ['1','2']:
            if as_path[-1] + '_' + ee_type in as_provider_map.keys():
                cert = Cert(isRoot=False, certName= dirs + '_EE_' + ee_type +'.crt', parentCert=parentDirs + '.crt',
                            allAS=as_all_map[as_path[-1]])
                seqConfName = cert.genSeqConf()
                keyPath = cert.genKey()
                csrPath = cert.genSeq(seqConfName, keyPath, isp_id_dict[as_path[-1]])
                cerPath = cert.caSigned(parentDirs + '.crt', csrPath, dirs + '_EE_' + ee_type +'.crt', seqConfName)

                aspa = Aspa(as_customer_map[as_path[-1]], as_provider_map[as_path[-1] + '_' + ee_type], dirs, ee_type)
                asn1filePath = aspa.genASN1Conf()
                aspaPath = aspa.genCMS(asn1filePath, keyPath, cerPath)






        # aspa = Aspa(as_customer_map[as_path[-1]], as_provider_map[as_path[-1]], dirs)
        # asn1filePath = aspa.genASN1Conf()
        #
        # aspaPath = aspa.genCMS(asn1filePath, keyPath, cerPath)




def resRelease():
    for root, dirs, files in os.walk(root_path, topdown=False):
        for name in files:
            crtfileName = os.path.join(root, name)
            cerfileName = crtfileName.replace(".crt",".cer")

            if crtfileName[-3:] == 'crt':
                if crtfileName.find('EE') == -1:
                    '''
                    openssl x509 -in eeserver.crt -out eeserver.cer -outform der
                    '''
                    cmd = "openssl x509   " + \
                          " -in " + crtfileName +  \
                          " -out " + cerfileName + \
                          " --outform der "

                    status, output = subprocess.getstatusoutput(cmd)
                    if status != 0:
                        print("cer tans faild, filename:", cerfileName," cmd",cmd, "reason:", output)
                        return

                #after tans crt to cer ,rm -rf crt
                cmd = "rm -rf  " + crtfileName
                status, output = subprocess.getstatusoutput(cmd)
                if status != 0:
                    print("rm crt faild, filename:", crtfileName, " cmd",cmd,"reason:", output)
                    return
    return



def main():
    as_path_dir, as_all_map, as_customer_map, as_provider_map, isp_id_dict = get_aspa_data()
    for i_index in range(len(as_path_dir)):
        for j_index in range(len(as_path_dir[i_index])):
            certSign(as_path_dir[i_index][:j_index+1], as_all_map, as_customer_map, as_provider_map, isp_id_dict)

    resRelease()





if __name__ == "__main__":
    main()

