typedef unsigned int u32;
u32 SingleScalar(u32 Count, u32 *Input) {
	u32 Sum = 0;
	for(u32 Index = 0; Index < Count; ++Index) {
		Sum += Input[Index];
	}
	return Sum;
}
