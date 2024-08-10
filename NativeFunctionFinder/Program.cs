using AsmResolver.PE;
using AsmResolver.PE.File;
using Iced.Intel;

namespace NativeFunctionFinder;

internal class Program
{
	static void Main(string[] args)
	{
		string filePath = args[0];

		byte[] fileData = File.ReadAllBytes(filePath);

		// Read the PE file
		var peFile = PEFile.FromBytes(fileData);

		var peImage = PEImage.FromFile(peFile);

		// Get the .text section (usually contains the executable code)
		var textSection = peFile.Sections.FirstOrDefault(s => s.Name == ".text");

		if (textSection?.Contents == null)
		{
			Console.WriteLine(".text section not found.");
			return;
		}

		List<ulong> addresses = FindAddresses(fileData, peFile, peImage, textSection);

		// Output all the addresses
		foreach (var address in addresses)
		{
			Console.WriteLine($"0x{address:X}");
		}

		FindTailCalls(fileData, peFile, textSection, addresses);

		Console.WriteLine();
		Console.WriteLine("Done!");
	}

	private static void FindTailCalls(byte[] fileData, PEFile peFile, PESection textSection, List<ulong> addresses)
	{
		Decoder decoder = CreateDecoder(fileData, peFile, textSection);
		foreach (var instruction in decoder)
		{
			if (instruction.IsJmpShortOrNear)
			{
				ulong targetAddress;

				// Determine if the call is relative or absolute
				if (instruction.IsIPRelativeMemoryOperand)
				{
					// Relative call
					targetAddress = decoder.IP + instruction.NearBranchTarget;
				}
				else
				{
					// Absolute call (can be direct or indirect)
					targetAddress = instruction.NearBranchTarget;
				}

				if (addresses.Contains(targetAddress))
				{
				}
			}
		}
	}

	private static List<ulong> FindAddresses(byte[] fileData, PEFile peFile, PEImage peImage, PESection textSection)
	{
		Decoder decoder = CreateDecoder(fileData, peFile, textSection);

		// Store all the addresses
		var addresses = new HashSet<ulong>();

		foreach (var instruction in decoder)
		{
			// Add the address to the list
			if (instruction.IsCallNear)
			{
				ulong targetAddress;

				// Determine if the call is relative or absolute
				if (instruction.IsIPRelativeMemoryOperand)
				{
					// Relative call
					targetAddress = decoder.IP + instruction.NearBranchTarget;
				}
				else
				{
					// Absolute call (can be direct or indirect)
					targetAddress = instruction.NearBranchTarget;
				}

				// Add the target address to the list
				addresses.Add(targetAddress);
			}
			else if (instruction.IsCallNearIndirect)
			{
			}
			else if (instruction.IsCallFar)
			{
			}
			else if (instruction.IsCallFarIndirect)
			{
			}
		}

		if (peFile.OptionalHeader.AddressOfEntryPoint != default)
		{
			ulong entryPointAddress = peFile.OptionalHeader.AddressOfEntryPoint + peFile.OptionalHeader.ImageBase;
			addresses.Add(entryPointAddress);
		}

		foreach (var export in peImage.Exports?.Entries ?? [])
		{
			ulong exportAddress = export.Address.Rva + peFile.OptionalHeader.ImageBase;
			addresses.Add(exportAddress);
		}

		return addresses.Order().ToList();
	}

	private static Decoder CreateDecoder(byte[] fileData, PEFile peFile, PESection textSection)
	{
		// Get the code bytes and the starting address
		var codeBytes = new ArraySegment<byte>(fileData, (int)textSection.Contents!.Offset, (int)textSection.GetPhysicalSize());
		ulong startAddress = peFile.OptionalHeader.ImageBase + textSection.Rva;

		// Disassemble the code
		ByteArrayCodeReader codeReader = new ByteArrayCodeReader(codeBytes);
		Decoder decoder = Decoder.Create(64, codeReader);
		decoder.IP = startAddress;

		return decoder;
	}
}
