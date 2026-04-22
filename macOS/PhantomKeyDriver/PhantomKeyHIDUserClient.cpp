#include <os/log.h>
#include <DriverKit/DriverKit.h>
#include <DriverKit/IOUserClient.h>
#include <DriverKit/IOBufferMemoryDescriptor.h>

#include "PhantomKeyHIDUserClient.h"
#include "PhantomKeyHIDDevice.h"

struct PhantomKeyHIDUserClient_IVars {
    PhantomKeyHIDDevice * device;
    OSAction *            reportCallback;
};

static kern_return_t externalMethodSendReport(OSObject * target,
                                               void * reference,
                                               IOUserClientMethodArguments * arguments);

static kern_return_t externalMethodRegisterReportCallback(OSObject * target,
                                                           void * reference,
                                                           IOUserClientMethodArguments * arguments);

static const IOUserClientMethodDispatch sMethods[kPhantomKeyMethodCount] = {
    [kPhantomKeyMethodSendReport] = {
        .function = externalMethodSendReport,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkStructureInputSize = 64,
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = 0,
    },
    [kPhantomKeyMethodRegisterReportCallback] = {
        .function = externalMethodRegisterReportCallback,
        .checkCompletionExists = true,
        .checkScalarInputCount = 0,
        .checkStructureInputSize = 0,
        .checkScalarOutputCount = 0,
        .checkStructureOutputSize = 0,
    },
};

bool PhantomKeyHIDUserClient::init()
{
    if (!super::init()) return false;
    ivars = IONewZero(PhantomKeyHIDUserClient_IVars, 1);
    if (!ivars) return false;
    return true;
}

void PhantomKeyHIDUserClient::free()
{
    if (ivars) {
        OSSafeReleaseNULL(ivars->reportCallback);
        IOSafeDeleteNULL(ivars, PhantomKeyHIDUserClient_IVars, 1);
    }
    super::free();
}

kern_return_t PhantomKeyHIDUserClient::Start_Impl(IOService_Start_Args)
{
    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDUserClient: Start");

    kern_return_t ret = Start(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        os_log(OS_LOG_DEFAULT, "PhantomKeyHIDUserClient: super::Start failed: 0x%x", ret);
        return ret;
    }

    ivars->device = OSDynamicCast(PhantomKeyHIDDevice, provider);
    if (!ivars->device) {
        os_log(OS_LOG_DEFAULT, "PhantomKeyHIDUserClient: provider is not PhantomKeyHIDDevice");
        return kIOReturnError;
    }
    ivars->device->setUserClient(this);

    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDUserClient: started successfully");
    return kIOReturnSuccess;
}

kern_return_t PhantomKeyHIDUserClient::Stop_Impl(IOService_Stop_Args)
{
    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDUserClient: Stop");
    if (ivars->device) {
        ivars->device->setUserClient(nullptr);
        ivars->device = nullptr;
    }
    OSSafeReleaseNULL(ivars->reportCallback);
    return Stop(provider, SUPERDISPATCH);
}

// ExternalMethod is a direct virtual override (not _Impl)
kern_return_t PhantomKeyHIDUserClient::ExternalMethod(
    uint64_t selector,
    IOUserClientMethodArguments * arguments,
    const IOUserClientMethodDispatch * dispatch,
    OSObject * target,
    void * reference)
{
    if (selector >= kPhantomKeyMethodCount) {
        return kIOReturnUnsupported;
    }
    return super::ExternalMethod(selector, arguments, &sMethods[selector], this, nullptr);
}

// LOCALONLY method — direct virtual override
void PhantomKeyHIDUserClient::setDevice(PhantomKeyHIDDevice * device)
{
    if (ivars) {
        ivars->device = device;
    }
}

static kern_return_t externalMethodSendReport(OSObject * target,
                                               void * reference,
                                               IOUserClientMethodArguments * arguments)
{
    auto self = OSDynamicCast(PhantomKeyHIDUserClient, target);
    if (!self || !self->ivars || !self->ivars->device) {
        return kIOReturnNotReady;
    }

    if (!arguments->structureInput) {
        return kIOReturnBadArgument;
    }

    const void * data = arguments->structureInput->getBytesNoCopy();
    uint32_t length = (uint32_t)arguments->structureInput->getLength();

    if (!data || length == 0 || length > 64) {
        return kIOReturnBadArgument;
    }

    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDUserClient: sendReport %u bytes", length);
    return self->ivars->device->postReport((const uint8_t *)data, length);
}

static kern_return_t externalMethodRegisterReportCallback(OSObject * target,
                                                           void * reference,
                                                           IOUserClientMethodArguments * arguments)
{
    auto self = OSDynamicCast(PhantomKeyHIDUserClient, target);
    if (!self || !self->ivars) {
        return kIOReturnNotReady;
    }
    if (!arguments->completion) {
        return kIOReturnBadArgument;
    }

    arguments->completion->retain();
    OSSafeReleaseNULL(self->ivars->reportCallback);
    self->ivars->reportCallback = arguments->completion;

    os_log(OS_LOG_DEFAULT, "PhantomKeyHIDUserClient: report callback registered");
    return kIOReturnSuccess;
}

kern_return_t PhantomKeyHIDUserClient::deliverSetReport(const uint8_t * data, uint32_t length)
{
    if (!ivars || !ivars->reportCallback) {
        return kIOReturnNotReady;
    }
    if (!data || length == 0 || length > 64) {
        return kIOReturnBadArgument;
    }

    // Pack the 64-byte (or shorter) HID report into 8 uint64_t slots for the
    // async scalar completion. Shorter reports are zero-padded.
    uint64_t asyncData[8] = {0};
    memcpy(asyncData, data, length);

    AsyncCompletion(ivars->reportCallback, kIOReturnSuccess, asyncData, 8);
    return kIOReturnSuccess;
}
