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

#include <core/core.h>

#define NYI_KEYSYSTEM "keysystem-placeholder"

#include <nexus_memory.h>

using namespace std;

namespace CDMi {

WPEFramework::Core::CriticalSection g_lock;

MediaKeySession::MediaKeySession(widevine::Cdm *cdm, int32_t licenseType)
    : m_cdm(cdm)
    , m_CDMData("")
    , m_initData("")
    , m_initDataType(widevine::Cdm::kCenc)
    , m_licenseType((widevine::Cdm::SessionType)licenseType)
    , m_sessionId("")
    , m_TokenHandle(nullptr)
    , m_pNexusMemory(nullptr)
    , m_NexusMemorySize(512 * 1024) {

  m_cdm->createSession(m_licenseType, &m_sessionId);

  ::memset(m_IV, 0 , sizeof(m_IV));

  NEXUS_Memory_Allocate(m_NexusMemorySize, nullptr, &m_pNexusMemory);
  if (!m_pNexusMemory) {
    printf("Memory allocation failure\n");
    m_NexusMemorySize = 0;
  }
}

MediaKeySession::~MediaKeySession(void) {

    if (m_pNexusMemory) {
      NEXUS_Memory_Free(m_pNexusMemory);
      m_NexusMemorySize = 0;
    }
}


void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {

  if (f_piMediaKeySessionCallback) {
    m_piCallback = const_cast<IMediaKeySessionCallback*>(f_piMediaKeySessionCallback);

    widevine::Cdm::Status status = m_cdm->generateRequest(m_sessionId, m_initDataType, m_initData);
    if (widevine::Cdm::kSuccess != status) {
       printf("generateRequest failed\n");
       m_piCallback->OnKeyMessage((const uint8_t *) "", 0, "");
    }
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
  case widevine::Cdm::kLicenseRenewal:
  case widevine::Cdm::kLicenseRelease:
  {
    destUrl.assign(kLicenseServer);

    // FIXME: Errrr, this is weird.
    //if ((Cdm::MessageType)f_message[1] == (Cdm::kIndividualizationRequest + 1)) {
    //  LOGI("switching message type to kIndividualizationRequest");
    //  messageType = Cdm::kIndividualizationRequest;
    //}

    message = std::to_string(f_messageType) + ":Type:";
    break;
  }
  default:
    printf("unsupported message type %d\n", f_messageType);
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
    m_piCallback->OnKeyStatusesUpdated();
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
  m_piCallback->OnError(0, CDMi_S_FALSE, errorStatus.c_str());
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
        m_piCallback->OnKeyStatusesUpdated();
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
  g_lock.Lock();
  widevine::Cdm::Status status = m_cdm->load(m_sessionId);
  if (widevine::Cdm::kSuccess != status)
    onKeyStatusError(status);
  else
    ret = CDMi_SUCCESS;
  g_lock.Unlock();
  return ret;
}

void MediaKeySession::Update(
    const uint8_t *f_pbKeyMessageResponse,
    uint32_t f_cbKeyMessageResponse) {
  std::string keyResponse(reinterpret_cast<const char*>(f_pbKeyMessageResponse),
      f_cbKeyMessageResponse);
  g_lock.Lock();
  widevine::Cdm::Status status = m_cdm->update(m_sessionId, keyResponse);
  if (widevine::Cdm::kSuccess != status)
     onKeyStatusChange();

  g_lock.Unlock();
}

CDMi_RESULT MediaKeySession::Remove(void) {
  CDMi_RESULT ret = CDMi_S_FALSE;
  g_lock.Lock();
  widevine::Cdm::Status status = m_cdm->remove(m_sessionId);
  if (widevine::Cdm::kSuccess != status)
    onKeyStatusError(status);
  else
    ret =  CDMi_SUCCESS;
  g_lock.Unlock();
  return ret;
}

CDMi_RESULT MediaKeySession::Close(void) {
  CDMi_RESULT status = CDMi_S_FALSE;
  g_lock.Lock();
  if (widevine::Cdm::kSuccess == m_cdm->close(m_sessionId))
    status = CDMi_SUCCESS;
  g_lock.Unlock();
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
    uint8_t *f_pbData,
    uint32_t f_cbData,
    uint32_t *f_pcbOpaqueClearContent,
    uint8_t **f_ppbOpaqueClearContent,
    const uint8_t keyIdLength,
    const uint8_t* keyId,
    bool /* initWithLast15 */)
{

  static NEXUS_HeapHandle secureHeap = NEXUS_Heap_Lookup(NEXUS_HeapLookupType_eCompressedRegion);

  g_lock.Lock();
  widevine::Cdm::KeyStatusMap map;
  std::string keyStatus;

  CDMi_RESULT status = CDMi_S_FALSE;
  *f_pcbOpaqueClearContent = 0;

  memcpy(m_IV, f_pbIV, (f_cbIV > 16 ? 16 : f_cbIV));
  if (f_cbIV < 16) {
    memset(&(m_IV[f_cbIV]), 0, 16 - f_cbIV);
  }

    // Reallocate input memory if needed.
  if (f_cbData >  m_NexusMemorySize) {

    void *newBuffer = nullptr;
    int rc = NEXUS_Memory_Allocate(f_cbData, nullptr, &newBuffer);
    if( rc != 0 ) {

        printf("NexusMemory to small, use larger buffer. could not allocate memory %d", f_cbData);
        return status;
    }

    NEXUS_Memory_Free(m_pNexusMemory);
    m_pNexusMemory = newBuffer;
    m_NexusMemorySize = f_cbData;
    printf("NexusMemory to small, use larger buffer. allocate memory %d", f_cbData);
  }


  NEXUS_MemoryBlockHandle pNexusMemoryBlock = NEXUS_MemoryBlock_Allocate(secureHeap, f_cbData, 0, nullptr);
  if (!pNexusMemoryBlock) {

    printf("NexusBlockMemory could not allocate %d", f_cbData);
    return status;
  }

  NEXUS_Error rc;
  void *pOpaqueData = nullptr;
  rc = NEXUS_MemoryBlock_Lock(pNexusMemoryBlock, &pOpaqueData);
  if (rc) {

    printf("NexusBlockMemory is not usable");
    NEXUS_MemoryBlock_Free(pNexusMemoryBlock);
    pOpaqueData = nullptr;
    return status;
  }

  m_TokenHandle = NEXUS_MemoryBlock_CreateToken(pNexusMemoryBlock);
  if (!m_TokenHandle) {

    printf("Could not create a token for another process");
    NEXUS_MemoryBlock_Unlock(pNexusMemoryBlock);
    NEXUS_MemoryBlock_Free(pNexusMemoryBlock);
    pOpaqueData = nullptr;
    return status;
  }

  // Copy provided payload to Input of Decryption.
  ::memcpy(m_pNexusMemory, f_pbData, f_cbData);

  if (widevine::Cdm::kSuccess == m_cdm->getKeyStatuses(m_sessionId, &map)) {
    widevine::Cdm::KeyStatusMap::iterator it = map.begin();
    // FIXME: We just check the first key? How do we know that's the Widevine key and not, say, a PlayReady one?
    if (widevine::Cdm::kUsable == it->second) {
      widevine::Cdm::OutputBuffer output;
      output.data = reinterpret_cast<uint8_t*>(pOpaqueData);
      output.data_length = f_cbData;
      output.is_secure = true;

      widevine::Cdm::InputBuffer input;
      input.data = reinterpret_cast<uint8_t*>(m_pNexusMemory);
      input.data_length = output.data_length;
      input.key_id = keyId;
      input.key_id_length = keyIdLength;
      input.iv = m_IV;
      input.iv_length = sizeof(m_IV);

      input.encryption_scheme = widevine::Cdm::kAesCtr;
      input.is_video = true;
      input.block_offset = 0;
      for (int ii = 15, counter = 0; ii >= 12; ii--, counter = counter >> 8) {
          m_IV[ii] = counter & 0xFF;
      }

      input.first_subsample = true;
      input.last_subsample  = true;
      if (widevine::Cdm::kSuccess == m_cdm->decrypt(input, output)) {
        status = CDMi_SUCCESS;
      } else {
        printf("CDM decrypt failed!\n");
      }
    }
  }

  //Copy and Return the Memory token in the incoming payload buffer.
  *f_pcbOpaqueClearContent = sizeof(m_TokenHandle);
  *f_ppbOpaqueClearContent = f_pbData;
  memcpy(*f_ppbOpaqueClearContent,reinterpret_cast<uint8_t*>(&m_TokenHandle),sizeof(m_TokenHandle));

  NEXUS_MemoryBlock_Unlock(pNexusMemoryBlock);
  NEXUS_MemoryBlock_Free(pNexusMemoryBlock);

  g_lock.Unlock();
  return status;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ){
  return CDMi_SUCCESS;
}
}  // namespace CDMi
