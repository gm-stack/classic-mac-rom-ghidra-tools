# TODO: make this a runnable script

###############
# Types for function returns
###############

# TODO: put these in a different script for function returns?
# TODO: along with code to find that function and set params/return type

# cpuid register definition including signature 
# as a separate field from value
# useful for the decompiler, not used anywhere in ROM.
cpuid = parseC("""struct cpuid {
	word cpuIDSig; // should be $A55A
	struct cpuIDValue cpuIDValue;
};""", subcategory='CPUID')

# return type for GetCPUIDReg
cpuid = parseC("""struct GetCPUIDReg_ret {
	struct cpuid cpuid;
	bool found;
};""", subcategory='func_returns', packing=1)

GetHardwareInfo_ret = parseC("""struct GetHardwareInfo_ret {
	addrDecoderInfo_shifted addrDecoderInfo;
	struct machineInfo *ProductInfo;
	struct baseAddrValidFlags baseAddrValidFlags;
	struct extFeatureFlags extFeaturesFlags;
	byte unused;
	struct hwCfgFlags hwCfgFlags;
	boxInfo boxInfo;
	memDecoderType memDecoderType;
};""", subcategory='func_returns', packing=1)

GetHardwareInfo_D2w = parseC("""struct GetHardwareInfo_D2w {
	boxInfo boxInfo;
	memDecoderType memDecoderType;
};""", subcategory='func_returns', packing=1)