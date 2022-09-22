typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

typedef NTSTATUS(WINAPI* _NtReadVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL);
	

typedef NTSTATUS(WINAPI* _NtSetContextThread)(
	IN HANDLE               ThreadHandle,
	IN PCONTEXT             Context
	);

typedef NTSTATUS(WINAPI* _NtResumeThread)(
	IN HANDLE               ThreadHandle,
	OUT PULONG              SuspendCount OPTIONAL
	);

typedef NTSTATUS(WINAPI* _NtWriteVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL
	);