// ©AngelaMos | 2026
// mediainfolib_buffer.cpp

#include <cstddef>
#include <cstdint>

#include "MediaInfo/MediaInfo.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    MediaInfoLib::MediaInfo handle;

    handle.Option(__T("Complete"), __T("1"));
    handle.Option(__T("ParseSpeed"), __T("1.0"));

    if (handle.Open_Buffer_Init(static_cast<ZenLib::int64u>(size), 0) == 0) {
        return 0;
    }

    handle.Open_Buffer_Continue(reinterpret_cast<const ZenLib::int8u *>(data), size);
    handle.Open_Buffer_Finalize();
    handle.Inform();
    handle.Close();

    return 0;
}
