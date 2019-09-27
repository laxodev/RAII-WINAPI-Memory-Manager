#pragma once
#include <Windows.h> 
#include <TlHelp32.h> 
#include <string> 
#include <memory> 
#include <cstdint>
#include <optional>
#include <string_view>
#include <type_traits>
#include <system_error>
// This is a user-defined "deleter" which gets passed to our smart-pointer. 
//It is required because smart-pointers call "delete" by default and we need "CloseHandle". It is used on WINAPI HANDLES.

namespace win_raii
{
	// Meant for internal usage only.
	namespace detail
	{
		struct HandleDisposer
		{
			// We do "using pointer = HANDLE" because a unique_ptr will check for a "pointer" type on our deleter struct. 
			// This also allows us to pass "HANDLE" to our unique_ptr. If we didn't do this it will be the equivalent of HANDLE* which is "void**"
			// We could pass a regular "void" which would end up as "void*" but it's much cleaner to use the typedef defined in the windows headers.
			using pointer = HANDLE;

			// operator that gets called when our object is going to be destroyed.

			void operator()(HANDLE handle) const
			{
				// we check for both INVALID_HANDLE_VALUE and NULL as not all winapi functions will return INVALID_HANDLE_VALUE.
				if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
				{
					CloseHandle(handle);
				}
			}
		};
		// WINAPI HANDLE wrapped around a unique_ptr, inside "detail" as this is mean't for internal use.
		using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;
	}
	enum SafeMemory_Access
	{
		SafeMemory_AllAccess = PROCESS_ALL_ACCESS,
		SafeMemory_ReadAccess = PROCESS_VM_READ,
		SafeMemory_WriteAccess = PROCESS_VM_WRITE,
		SafeMemory_Operation = PROCESS_VM_OPERATION
	};
	class SafeMemory
	{
	public:
		// Acquires the process-id and opens the handle based on the process-name. 
		//Functions labled as "noexcept(false)" mean that it will throw a exception upon failure. Regular "noexcepts" are safe to use without any try/catch handling.
		struct ConstructProcessName {};
		struct ConstructWindowName {};
		struct ConstructProcessID {};

		explicit SafeMemory(std::wstring_view process_name, const SafeMemory_Access processFlags, ConstructProcessName) noexcept(false)
		{
			// Acquire the handle in the constructor.
			const std::optional<std::uint32_t> process_id = this->AcquireProcessID(process_name);

			if (!process_id.has_value() || !this->AcquireProcessHandle(process_id.value(), processFlags) || !SetHandleInformation(this->m_processHandle.get(), HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE))
				throw std::system_error(GetLastError(), std::system_category(), "Failed to open a handle to the specified process. An error code has been returned");

			this->m_processID = process_id.value();
		}
		// Acquires the process-id and opens the handle based on the window-name.
		explicit SafeMemory(const std::wstring& window_name, const SafeMemory_Access processFlags, ConstructWindowName) noexcept(false)
		{
			// Acquire the handle in the constructor.
			const std::optional<std::uint32_t> process_id = this->AcquireProcessIDByWindowName(window_name);

			if (!process_id.has_value() || !this->AcquireProcessHandle(process_id.value(), processFlags) || !SetHandleInformation(this->m_processHandle.get(), HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE))
				throw std::system_error(GetLastError(), std::system_category(), "Failed to open a handle to the specified process. An error code has been returned");

			this->m_processID = process_id.value();
		}
		// Opens the handle based on the process-id passed to the constructor.
		explicit SafeMemory(const std::uint32_t process_id, const SafeMemory_Access processFlags, ConstructProcessID) noexcept(false)
		{
			if (!process_id || !this->AcquireProcessHandle(process_id, processFlags) || !SetHandleInformation(this->m_processHandle.get(), HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE))
				throw std::system_error(GetLastError(), std::system_category(), "Failed to open a handle to the specified process. An error code has been returned");

			this->m_processID = process_id;
		}
		// Disables the copy ctor and copy assignment operator to ensure no copy of the object is created.
		// If a copy is made and the original one goes out of scope will be left with a invalid handle.
		// This shouldn't be copyable anyway since we are using a handle wrapped around a unique_ptr.
		// If it is intended for a function to take this object it should be passed by reference.
		SafeMemory(const SafeMemory&) = delete;
		SafeMemory& operator = (const SafeMemory&) = delete;
		~SafeMemory() { SetHandleInformation(this->m_processHandle.get(), HANDLE_FLAG_PROTECT_FROM_CLOSE, NULL); }
	private:
		// Main handle that lives throughout until the object-lifetime is over.
		win_raii::detail::unique_handle m_processHandle;
		std::uint32_t m_processID = 0;
	private:
		// Acquires the process id by process-name.
		inline std::optional<std::uint32_t> AcquireProcessID(std::wstring_view process_name) const noexcept
		{
			PROCESSENTRY32W processentry;
			const win_raii::detail::unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

			if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
				return std::nullopt;

			processentry.dwSize = sizeof(PROCESSENTRY32W);

			if (Process32FirstW(snapshot_handle.get(), &processentry)) {

				while (Process32NextW(snapshot_handle.get(), &processentry)) {
					if (process_name == processentry.szExeFile)
						return std::optional<std::uint32_t>(processentry.th32ProcessID);
				}
			}
			return std::nullopt;
		}
		// Acquires the process id by the window-name.
		// We cannot use "c_str" to return a null-terminated character array like we would with a regular std::string.
		inline std::optional<std::uint32_t> AcquireProcessIDByWindowName(const std::wstring& window_name) const noexcept
		{
			DWORD temp_process_id = 0;

			const HWND window_handle(FindWindowW(0, window_name.c_str()));

			if (window_handle == nullptr)
				return std::nullopt;

			if (GetWindowThreadProcessId(window_handle, &temp_process_id) == 0)
				return std::nullopt;

			return std::optional<std::uint32_t>(temp_process_id);
		}
		// Opens the specified handle.
		bool AcquireProcessHandle(const std::uint32_t process_id, const DWORD processFlags) noexcept
		{
			std::optional<win_raii::detail::unique_handle> processhandle = CreateProcessHandle(process_id, processFlags);

			if (!processhandle.has_value())
				return false;

			this->m_processHandle = std::move(processhandle.value());

			return true;
		}
		// Creates a handle.
		std::optional<win_raii::detail::unique_handle> CreateProcessHandle(const std::uint32_t process_id, const DWORD processFlags) const noexcept
		{
			// Passes the ownership to the main handle.
			win_raii::detail::unique_handle processhandle(OpenProcess(processFlags, false, process_id));

			if (processhandle.get() == nullptr)
				return std::nullopt;

			return std::optional<win_raii::detail::unique_handle>(std::move(processhandle));
		}
	public:
		inline std::optional<std::uintptr_t> GetModuleBaseAddress(std::wstring_view module_name) const noexcept
		{
			MODULEENTRY32W moduleentry;

			const win_raii::detail::unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->m_processID));

			if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
				return std::nullopt;
			
			moduleentry.dwSize = sizeof(MODULEENTRY32W);

			if (Module32FirstW(snapshot_handle.get(), &moduleentry)) {

				while (Module32NextW(snapshot_handle.get(), &moduleentry)) {
					if (module_name == moduleentry.szModule)
						return std::optional<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(moduleentry.modBaseAddr));
				}
			}
			return std::nullopt;
		}
	public:
		// RPM/WPM 
		template<typename T>
		std::optional<T> SafeReadMemory(const std::uintptr_t address_ptr) const noexcept(false)
		{
			std::optional<T> length;

			if ((!ReadProcessMemory(this->m_processHandle.get(), reinterpret_cast<void*>(address_ptr), std::addressof(length), sizeof(length), 0))) {
				return std::nullopt;
			}
			return length;
		}
		template<typename T>
		bool SafeWriteMemory(const std::uintptr_t address_ptr, const T& length) const noexcept
		{
			return !!WriteProcessMemory(this->m_processHandle.get(), reinterpret_cast<void*>(address_ptr), std::addressof(length), sizeof(length), 0);
		}
	};
}
