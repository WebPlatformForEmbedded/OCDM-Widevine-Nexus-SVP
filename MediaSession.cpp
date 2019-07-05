/*
 * Copyright 2016-2017 TATA ELXSI
 * Copyright 2016-2017 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "MediaSession.h"
#include "Policy.h"

#include <assert.h>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <string.h>
#include <sys/utsname.h>

#define NYI_KEYSYSTEM "keysystem-placeholder"

#include <refsw/b_secbuf.h>

#include <functional>
#include <thread>

struct Rpc_Secbuf_Info {
    uint32_t type;
    size_t   size;
    void    *token;
    void    *token_enc;
    uint32_t subsamples_count;
    uint32_t subsamples[];
};

using namespace std;

namespace CDMi {

MediaKeySession::MediaKeySession(widevine::Cdm *cdm, int32_t licenseType)
    : m_cdm(cdm)
    , m_CDMData("")
    , m_initData("")
    , m_initDataType(widevine::Cdm::kCenc)
    , m_licenseType((widevine::Cdm::SessionType)licenseType)
    , m_sessionId("") {
  m_cdm->createSession(m_licenseType, &m_sessionId);

  ::memset(m_IV, 0 , sizeof(m_IV));;
}

MediaKeySession::~MediaKeySession(void) {
}


void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {

  if (f_piMediaKeySessionCallback) {
    m_piCallback = const_cast<IMediaKeySessionCallback*>(f_piMediaKeySessionCallback);

    widevine::Cdm::Status status = m_cdm->generateRequest(m_sessionId, m_initDataType, m_initData);
    if (widevine::Cdm::kSuccess != status)
       printf("generateRequest failed\n");
  }
  else {
      m_piCallback = nullptr;
  }
}

void MediaKeySession::onMessage(widevine::Cdm::MessageType f_messageType, const std::string& f_message) {
  std::string destUrl;
  std::string message;

  switch (f_messageType) {
  case widevine::Cdm::kLicenseRequest:
  {
    destUrl.assign(kLicenseServer); 
    widevine::Cdm::MessageType messageType = widevine::Cdm::kLicenseRequest;

    // FIXME: Errrr, this is weird.
    //if ((Cdm::MessageType)f_message[1] == (Cdm::kIndividualizationRequest + 1)) {
    //  LOGI("switching message type to kIndividualizationRequest");
    //  messageType = Cdm::kIndividualizationRequest;
    //}
    
    message = std::to_string(messageType) + ":Type:";
    break;
  }
  default:
    printf("unsupported message type\n");
    break;
  }
  message.append(f_message.c_str(),  f_message.size());
  m_piCallback->OnKeyMessage((const uint8_t*) message.c_str(), message.size(), (char*) destUrl.c_str());
}

static const char* widevineKeyStatusToCString(widevine::Cdm::KeyStatus widevineStatus)
{
    switch (widevineStatus) {
    case widevine::Cdm::kUsable:
        return "KeyUsable";
        break;
    case widevine::Cdm::kExpired:
        return "KeyExpired";
        break;
    case widevine::Cdm::kOutputRestricted:
        return "KeyOutputRestricted";
        break;
    case widevine::Cdm::kStatusPending:
        return "KeyStatusPending";
        break;
    case widevine::Cdm::kInternalError:
        return "KeyInternalError";
        break;
    case widevine::Cdm::kReleased:
        return "KeyReleased";
        break;
    default:
        return "UnknownError";
        break;
    }
}

void MediaKeySession::onKeyStatusChange()
{
    std::thread(std::bind(&MediaKeySession::deferredKeyStatusChange, this)).detach();
}

void MediaKeySession::deferredKeyStatusChange()
{
    widevine::Cdm::KeyStatusMap map;
    if (widevine::Cdm::kSuccess != m_cdm->getKeyStatuses(m_sessionId, &map))
        return;

    for (const auto& pair : map) {
        const std::string& keyValue = pair.first;
        widevine::Cdm::KeyStatus keyStatus = pair.second;

        m_piCallback->OnKeyStatusUpdate(widevineKeyStatusToCString(keyStatus),
                                        reinterpret_cast<const uint8_t*>(keyValue.c_str()),
                                        keyValue.length());
    }
}

void MediaKeySession::onKeyStatusError(widevine::Cdm::Status status) {
  std::string errorStatus;
  switch (status) {
  case widevine::Cdm::kNeedsDeviceCertificate:
    errorStatus = "NeedsDeviceCertificate";
    break;
  case widevine::Cdm::kSessionNotFound:
    errorStatus = "SessionNotFound";
    break;
  case widevine::Cdm::kDecryptError:
    errorStatus = "DecryptError";
    break;
  case widevine::Cdm::kTypeError:
    errorStatus = "TypeError";
    break;
  case widevine::Cdm::kQuotaExceeded:
    errorStatus = "QuotaExceeded";
    break;
  case widevine::Cdm::kNotSupported:
    errorStatus = "NotSupported";
    break;
  default:
    errorStatus = "UnExpectedError";
    break;
  }
  m_piCallback->OnKeyError(0, CDMi_S_FALSE, errorStatus.c_str());
}

void MediaKeySession::onRemoveComplete() {
    widevine::Cdm::KeyStatusMap map;
    if (widevine::Cdm::kSuccess == m_cdm->getKeyStatuses(m_sessionId, &map)) {
        for (const auto& pair : map) {
            const std::string& keyValue = pair.first;

            m_piCallback->OnKeyStatusUpdate("KeyReleased",
                                        reinterpret_cast<const uint8_t*>(keyValue.c_str()),
                                        keyValue.length());
        }
    }
}

void MediaKeySession::onDeferredComplete(widevine::Cdm::Status) {
}

void MediaKeySession::onDirectIndividualizationRequest(
        const std::string& session_id,
        const std::string& request) {
}

CDMi_RESULT MediaKeySession::Load(void) {
  CDMi_RESULT ret = CDMi_S_FALSE;
  widevine::Cdm::Status status = m_cdm->load(m_sessionId);
  if (widevine::Cdm::kSuccess != status)
    onKeyStatusError(status);
  else
    ret = CDMi_SUCCESS;
  return ret;
}

void MediaKeySession::Update(
    const uint8_t *f_pbKeyMessageResponse,
    uint32_t f_cbKeyMessageResponse) {
  std::string keyResponse(reinterpret_cast<const char*>(f_pbKeyMessageResponse),
      f_cbKeyMessageResponse);
  if (widevine::Cdm::kSuccess != m_cdm->update(m_sessionId, keyResponse))
     onKeyStatusChange();
}

CDMi_RESULT MediaKeySession::Remove(void) {
  CDMi_RESULT ret = CDMi_S_FALSE;
  widevine::Cdm::Status status = m_cdm->remove(m_sessionId);
  if (widevine::Cdm::kSuccess != status)
    onKeyStatusError(status);
  else
    ret =  CDMi_SUCCESS;
  return ret;
}

CDMi_RESULT MediaKeySession::Close(void) {
  CDMi_RESULT status = CDMi_S_FALSE;
  if (widevine::Cdm::kSuccess == m_cdm->close(m_sessionId))
    status = CDMi_SUCCESS;
  return status;
}

const char* MediaKeySession::GetSessionId(void) const {
  return m_sessionId.c_str();
}

const char* MediaKeySession::GetKeySystem(void) const {
  return NYI_KEYSYSTEM;//TODO: replace with keysystem and test
}

CDMi_RESULT MediaKeySession::Init(
    int32_t licenseType,
    const char *f_pwszInitDataType,
    const uint8_t *f_pbInitData,
    uint32_t f_cbInitData,
    const uint8_t *f_pbCDMData,
    uint32_t f_cbCDMData) {
  switch ((LicenseType)licenseType) {
  case PersistentUsageRecord:
    m_licenseType = widevine::Cdm::kPersistentUsageRecord;
    break;
  case PersistentLicense:
    m_licenseType = widevine::Cdm::kPersistentLicense;
    break;
  default:
    m_licenseType = widevine::Cdm::kTemporary;
    break;
  }

  if (f_pwszInitDataType) {
    if (!strcmp(f_pwszInitDataType, "cenc"))
       m_initDataType = widevine::Cdm::kCenc;
    else if (!strcmp(f_pwszInitDataType, "webm"))
       m_initDataType = widevine::Cdm::kWebM;
  }

  if (f_pbInitData && f_cbInitData)
    m_initData.assign((const char*) f_pbInitData, f_cbInitData);

  if (f_pbCDMData && f_cbCDMData)
    m_CDMData.assign((const char*) f_pbCDMData, f_cbCDMData);
  return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::Decrypt(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t *f_pdwSubSampleMapping,
    uint32_t f_cdwSubSampleMapping,
    const uint8_t *f_pbIV,
    uint32_t f_cbIV,
    const uint8_t *f_pbData,
    uint32_t f_cbData,
    uint32_t *f_pcbOpaqueClearContent,
    uint8_t **f_ppbOpaqueClearContent,
    const uint8_t keyIdLength,
    const uint8_t* keyId,
    bool /* initWithLast15 */)
{
  widevine::Cdm::KeyStatusMap map;
  std::string keyStatus;

  CDMi_RESULT status = CDMi_S_FALSE;
  *f_pcbOpaqueClearContent = 0;

  memcpy(m_IV, f_pbIV, (f_cbIV > 16 ? 16 : f_cbIV));
  if (f_cbIV < 16) {
    memset(&(m_IV[f_cbIV]), 0, 16 - f_cbIV);
  }

  Rpc_Secbuf_Info *pRPCsecureBufferInfo;
  B_Secbuf_Info secureBufferInfo;

  void *pOpaqueData, *pOpaqueDataEnc;

  pRPCsecureBufferInfo = static_cast<Rpc_Secbuf_Info*>(::malloc(f_cbData));
  ::memcpy(pRPCsecureBufferInfo, f_pbData, f_cbData);

  // Allocate a secure buffer for decrypted data, output of decrypt
  if (B_Secbuf_Alloc(pRPCsecureBufferInfo->size, B_Secbuf_Type_eSecure, &pOpaqueData)) {
        printf("B_Secbuf_Alloc() failed!\n");
        return status;
  }
  B_Secbuf_GetBufferInfo(pOpaqueData, &secureBufferInfo);
  pRPCsecureBufferInfo->token = secureBufferInfo.token;
  ::memcpy((void*)f_pbData, pRPCsecureBufferInfo, f_cbData); // Update token for WPE to get the secure buffer

  // Allocate with a token for encrypted data, input of decrypt
  if (B_Secbuf_AllocWithToken(pRPCsecureBufferInfo->size, B_Secbuf_Type_eGeneric, pRPCsecureBufferInfo->token_enc, &pOpaqueDataEnc)) {
        printf("B_Secbuf_AllocWithToken() failed!\n");
        return status;
  }
  // copy all samples data including clear one too
  B_Secbuf_ImportData(pOpaqueData, 0, (unsigned char*)pOpaqueDataEnc, pRPCsecureBufferInfo->size, 1);

  if (widevine::Cdm::kSuccess == m_cdm->getKeyStatuses(m_sessionId, &map)) {
    widevine::Cdm::KeyStatusMap::iterator it = map.begin();
    // FIXME: We just check the first key? How do we know that's the Widevine key and not, say, a PlayReady one?
    if (widevine::Cdm::kUsable == it->second) {
      widevine::Cdm::OutputBuffer output;

      uint32_t inClear, inEncrypted,  inTotal = 0, totalEncrypted = 0;
      for(uint32_t i = 0; i < pRPCsecureBufferInfo->subsamples_count/2; i++) {
        inClear     = pRPCsecureBufferInfo->subsamples[2*i+0];
        inEncrypted = pRPCsecureBufferInfo->subsamples[2*i+1];
        output.data = reinterpret_cast<uint8_t*>(pOpaqueData)+inTotal+inClear;
        output.data_length = inEncrypted;
        output.is_secure = true;

        widevine::Cdm::InputBuffer input;
        input.data = reinterpret_cast<uint8_t*>(pOpaqueDataEnc)+inTotal+inClear;
        input.data_length = output.data_length;
        input.key_id = keyId;
        input.key_id_length = keyIdLength;
        input.iv = m_IV;
        input.iv_length = sizeof(m_IV);

        input.encryption_scheme = widevine::Cdm::kAesCtr;
        input.is_video = true;
        input.block_offset = (totalEncrypted)%16;
        for (int ii = 15, counter = (totalEncrypted)/ 16; ii >= 12; ii--, counter = counter >> 8) {
            m_IV[ii] = counter & 0xFF;
        }

        input.first_subsample = i==0 ? true : false;
        input.last_subsample  = i==(pRPCsecureBufferInfo->subsamples_count/2 -1 ) ? true : false;
        if (widevine::Cdm::kSuccess == m_cdm->decrypt(input, output)) {
          status = CDMi_SUCCESS;
        } else {
          printf("CDM decrypt failed!\n");
          break;
        }
        inTotal += inClear + inEncrypted;
        totalEncrypted += inEncrypted;

      } // subsampling loop
    }
  }

  ::free(pRPCsecureBufferInfo);
  // only freeing desc here, pOpaqueData will be freed by WPE in gstreamer
  B_Secbuf_FreeDesc(pOpaqueData);
  // Encrypted data does not need anymore, freeing
  B_Secbuf_Free(pOpaqueDataEnc);

  return status;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ){
  CDMi_RESULT ret = CDMi_S_FALSE;
  if (f_pbClearContentOpaque) {
    free(f_pbClearContentOpaque);
    ret = CDMi_SUCCESS;
  }
  return ret;
}
}  // namespace CDMi
