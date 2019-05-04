# RAII-WINAPI-Memory-Manager
Simple Windows API memory-editing class which incorporates RAII. 


Try/Catch handling should be performed during object construction. All three constructors are marked as noexcept(false)


Construct and obtain handle by process_name.
```

	try {
		win_raii::SafeMemory memorymanager("program.exe", win_raii::SafeMemory_Access::SafeMemory_AllAccess, win_raii::SafeMemory::ConstructProcessName{});
	}
	catch (const std::system_error& e) {
		std::cout << "Exception thrown! " << e.what() << std::endl;
		std::cout << "winapi error_code " << e.code() << std::endl;
	} 

}
```

Construct and obtain handle by window_name.

```

	try {
		win_raii::SafeMemory memorymanager("Window Name", win_raii::SafeMemory_Access::SafeMemory_AllAccess, win_raii::SafeMemory::ConstructWindowName{});
	}
	catch (const std::system_error& e) {
		std::cout << "Exception thrown! " << e.what() << std::endl;
		std::cout << "winapi error_code " << e.code() << std::endl;
	} 
  ```
  
  Construct and obtain handle by regular process-id.
  
  ```
	try {
		std::uint32_t process_id = 1000;
		win_raii::SafeMemory(process_id, win_raii::SafeMemory_Access::SafeMemory_AllAccess, win_raii::SafeMemory::ConstructProcessID{});
	}
	catch (const std::system_error& e) {
		std::cout << "Exception thrown! " << e.what() << std::endl;
		std::cout << "winapi error_code " << e.code() << std::endl;
	}
  ```
