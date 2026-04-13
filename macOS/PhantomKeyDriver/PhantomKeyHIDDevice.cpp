#include <os/log.h>
#include <DriverKit/DriverKit.h>
#include <DriverKit/IOBufferMemoryDescriptor.h>
#include <HIDDriverKit/HIDDriverKit.h>

#include "PhantomKeyHIDDevice.h"

// FIDO Alliance HID descriptor: usage page 0xF1D0, usage 0x01, 64-byte reports
static const uint8_t kFIDOHIDDescriptor[] = {
    0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance)
    0x09, 0x01,         // Usage (U2F HID Authenticator Device)
    0xA1, 0x01,         // Collection (Application)
    0x09, 0x20,         //   Usage (Input Report Data)
    0x15, 0x00,         //   Logical Minimum (0)
    0x26, 0xFF, 0x00,   //   Logical Maximum (255)
    0x75, 0x08,         //   Report Size (8 bits)
    0x95, 0x40,         //   Report Count (64)
    0x81, 0x02,         //   Input (Data, Variable, Absolute)
    0x09, 0x21,         //   Usage (Output Report Data)
    0x15, 0x00,         //   Logical Minimum (0)
    0x26, 0xFF, 0x00,   //   Logical Maximum (255)
    0x75, 0x08,         //   Report Size (8 bits)
    0x95, 0x40,         //   Report Count (64)
    0x91, 0x02,         //   Output (Data, Variable, Absolute)
    0xC0                // End Collection
};

struct PhantomKeyHIDDevice_IVars {
    OSData * reportDescriptor;
};

bool PhantomKeyHIDDevice::init()
{
    if (!super::init()) return false;
    ivars = IONewZero(PhantomKeyHIDDevice_IVars, 1);
    if (!ivars) return false;
    return true;
}

void PhantomKeyHIDDevice::free()
{
    if (ivars) {
        OSSafeReleaseNULL(ivars->reportDescriptor);
        IOSafeDeleteNULL(ivars, PhantomKeyHIDDevice_IVars, 1);
    }
    super::free();
}

// Start and Stop use _Impl pattern (they cross the kernel boundary)
kern_return_t PhantomKeyHIDDevice::Start_Impl(IOService_Start_Args)
{
    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDDevice: Start");

    kern_return_t ret = Start(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        os_log(OS_LOG_DEFAULT, "PhantomKeyHIDDevice: super::Start failed: 0x%x", ret);
        return ret;
    }

    ivars->reportDescriptor = OSData::withBytes(kFIDOHIDDescriptor, sizeof(kFIDOHIDDescriptor));
    if (!ivars->reportDescriptor) {
        return kIOReturnNoMemory;
    }

    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDDevice: started successfully");
    return kIOReturnSuccess;
}

kern_return_t PhantomKeyHIDDevice::Stop_Impl(IOService_Stop_Args)
{
    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDDevice: Stop");
    return Stop(provider, SUPERDISPATCH);
}

// Virtual method overrides (no _Impl suffix — these are LOCALONLY or direct overrides)
OSDictionary * PhantomKeyHIDDevice::newDeviceDescription()
{
    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDDevice: newDeviceDescription");

    auto dict = OSDictionary::withCapacity(10);
    if (!dict) return nullptr;

    auto vendorID     = OSNumber::withNumber((uint64_t)0x1209, 32);
    auto productID    = OSNumber::withNumber((uint64_t)0xF1D0, 32);
    auto manufacturer = OSString::withCString("PhantomKey");
    auto product      = OSString::withCString("PhantomKey FIDO2 Authenticator");
    auto serial       = OSString::withCString("PK-001");
    auto transport    = OSString::withCString("Virtual");
    auto countryCode  = OSNumber::withNumber((uint64_t)0, 32);

    dict->setObject(kIOHIDVendorIDKey, vendorID);
    dict->setObject(kIOHIDProductIDKey, productID);
    dict->setObject(kIOHIDManufacturerKey, manufacturer);
    dict->setObject(kIOHIDProductKey, product);
    dict->setObject(kIOHIDSerialNumberKey, serial);
    dict->setObject(kIOHIDTransportKey, transport);
    dict->setObject(kIOHIDCountryCodeKey, countryCode);

    OSSafeReleaseNULL(vendorID);
    OSSafeReleaseNULL(productID);
    OSSafeReleaseNULL(manufacturer);
    OSSafeReleaseNULL(product);
    OSSafeReleaseNULL(serial);
    OSSafeReleaseNULL(transport);
    OSSafeReleaseNULL(countryCode);

    return dict;
}

OSData * PhantomKeyHIDDevice::newReportDescriptor()
{
    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDDevice: newReportDescriptor");
    if (ivars && ivars->reportDescriptor) {
        ivars->reportDescriptor->retain();
        return ivars->reportDescriptor;
    }
    return OSData::withBytes(kFIDOHIDDescriptor, sizeof(kFIDOHIDDescriptor));
}

kern_return_t PhantomKeyHIDDevice::getReport(
    IOMemoryDescriptor * report,
    IOHIDReportType reportType,
    IOOptionBits options,
    uint32_t completionTimeout,
    OSAction * action)
{
    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDDevice: getReport type=%d", (int)reportType);
    return kIOReturnSuccess;
}

kern_return_t PhantomKeyHIDDevice::setReport(
    IOMemoryDescriptor * report,
    IOHIDReportType reportType,
    IOOptionBits options,
    uint32_t completionTimeout,
    OSAction * action)
{
    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDDevice: setReport type=%d", (int)reportType);

    if (!report) return kIOReturnBadArgument;

    uint64_t length = 0;
    report->GetLength(&length);
    if (length == 0 || length > 64) return kIOReturnBadArgument;

    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDDevice: received %llu byte output report", length);
    return kIOReturnSuccess;
}

kern_return_t PhantomKeyHIDDevice::postReport(const uint8_t * reportData, uint32_t reportLength)
{
    if (!reportData || reportLength == 0 || reportLength > 64) {
        return kIOReturnBadArgument;
    }

    IOBufferMemoryDescriptor * buffer = nullptr;
    kern_return_t ret = IOBufferMemoryDescriptor::Create(
        kIOMemoryDirectionInOut, reportLength, 0, &buffer);
    if (ret != kIOReturnSuccess || !buffer) {
        return kIOReturnNoMemory;
    }

    uint64_t address = 0;
    uint64_t length = 0;
    buffer->Map(0, 0, 0, 0, &address, &length);
    if (address && length >= reportLength) {
        memcpy((void *)address, reportData, reportLength);
    }

    ret = handleReport(mach_absolute_time(), buffer, reportLength, kIOHIDReportTypeInput, 0);

    OSSafeReleaseNULL(buffer);
    return ret;
}
