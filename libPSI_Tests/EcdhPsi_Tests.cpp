#include "EcdhPsi_Tests.h"

#include "cryptoTools/Network/Endpoint.h"
#include "Common.h"
#include "cryptoTools/Common/Defines.h"
#include "libPSI/PSI/ECDH/EcdhPsiReceiver.h"
#include "libPSI/PSI/ECDH/EcdhPsiSender.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Network/IOService.h"
//
//#include "cryptopp/aes.h"
//#include "cryptopp/modes.h"
//#include "MyAssert.h"
#include <array>
#include "libPSI/Tools/SimpleIndex.h"

using namespace osuCrypto;



void Simple_HashingParameters_Calculation() {
#if 1
	SimpleIndex simpleIndex;
	/*std::vector<u64> logNumBalls{ 8,10, 12,14, 16,18, 20,22, 24 };
	std::vector<u64> lengthCodeWord{ 424,432, 432, 440,440, 448, 448, 448, 448 };
*/
	std::vector<u64> logNumBalls{  16};
	std::vector<u64> lengthCodeWord{ 440};

	u64 statSecParam = 40, lengthItem = 128, compSecParam = 128;
	u64 commCost;
	double scale = 0, m = 0;
	double iScaleStart = 0.01, iScaleEnd = 0.12;

	for (u64 idxN = 0; idxN < logNumBalls.size(); idxN++)
	{
		u64 numBalls = 1 << logNumBalls[idxN];
		double iScale = iScaleStart;
		while (iScale < iScaleEnd)
		{
			u64 numBins = iScale*numBalls;
			u64 maxBinSize = simpleIndex.get_bin_size(numBins, numBalls, statSecParam);
			u64 polyBytes = (statSecParam + log2(pow(maxBinSize + 1, 2)*numBins));
			u64 curCommCost = numBins * (maxBinSize + 1)*(
				lengthCodeWord[idxN]
				+ (maxBinSize + 1)*polyBytes //poly
				+ (lengthCodeWord[idxN] + statSecParam) //peqt
				+ (1 + lengthItem));//ot


			if (iScale == iScaleStart)
			{
				commCost = curCommCost;
				scale = iScale;
				m = maxBinSize;
			}
			std::cout << iScale << "\t" << numBins << "\t" << maxBinSize << "\t"
				<< curCommCost << " bits = " << (curCommCost / 8)*pow(10, -6) << " Mb \t "
				<< commCost << " bits = " << (commCost / 8)*pow(10, -6) << " Mb \t ";

			if (commCost > curCommCost)
			{
				commCost = curCommCost;
				scale = iScale;
				m = maxBinSize;

			}

			std::cout << scale << std::endl;

			//std::cout << iScale << "\t" << commCost <<"\t"<< curCommCost << std::endl;
			iScale += 0.001;
		}
		std::cout << "##############" << std::endl;
		std::cout << logNumBalls[idxN] << "\t" << scale << "\t" << m << "\t" << (commCost / 8)*pow(10, -6) << " Mb" << std::endl;
		std::cout << "##############" << std::endl;

	}
#endif	
}


void EcdhPsi_EmptrySet_Test_Impl()
{
	u64 setSize = 8, psiSecParam = 40;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = prng.get<block>();
		recvSet[i] = prng.get<block>();
	}

	std::string name("psi");

	IOService ios(0);
	Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
	Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);


	std::vector<Channel> recvChl{ ep1.addChannel(name, name) };
	std::vector<Channel> sendChl{ ep0.addChannel(name, name) };

	EcdhPsiSender send;
	EcdhPsiReceiver recv;
	std::thread thrd([&]() {

		send.init(setSize, psiSecParam, prng.get<block>());
		send.sendInput(sendSet, sendChl);
	});

	recv.init(setSize, psiSecParam, ZeroBlock);
	recv.sendInput(recvSet, recvChl);

	thrd.join();

	sendChl[0].close();
	recvChl[0].close();

	ep0.stop();
	ep1.stop();
	ios.stop();
}

void EcdhPsi_FullSet_Test_Impl()
{
	setThreadName("CP_Test_Thread");
	u64 setSize = 40, psiSecParam = 40, numThreads(2);
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = recvSet[i] = prng.get<block>();
	}

	std::shuffle(sendSet.begin(), sendSet.end(), prng);


	std::string name("psi");

	IOService ios(0);
	Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
	Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);


	std::vector<Channel> sendChls(numThreads), recvChls(numThreads);
	for (u64 i = 0; i < numThreads; ++i)
	{
		sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
		recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
	}

	EcdhPsiSender send;
	EcdhPsiReceiver recv;
	std::thread thrd([&]() {

		send.init(setSize, psiSecParam, prng.get<block>());
		send.sendInput(sendSet, sendChls);
	});

	recv.init(setSize, psiSecParam, ZeroBlock);
	recv.sendInput(recvSet, recvChls);

	if (recv.mIntersection.size() != setSize)
		throw UnitTestFail();

	thrd.join();

	for (u64 i = 0; i < numThreads; ++i)
	{
		sendChls[i].close();// = &ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
		recvChls[i].close();// = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
	}

	ep0.stop();
	ep1.stop();
	ios.stop();

}

void EcdhPsi_SingltonSet_Test_Impl()
{
	setThreadName("Sender");
	u64 setSize = 40, psiSecParam = 40;

	PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));

	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = prng.get<block>();
		recvSet[i] = prng.get<block>();
	}

	sendSet[0] = recvSet[0];

	std::string name("psi");
	IOService ios(0);
	Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
	Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);


	std::vector<Channel> recvChl = { ep1.addChannel(name, name) };
	std::vector<Channel> sendChl = { ep0.addChannel(name, name) };


	EcdhPsiSender send;
	EcdhPsiReceiver recv;
	std::thread thrd([&]() {

		send.init(setSize, psiSecParam, prng.get<block>());
		send.sendInput(sendSet, sendChl);
	});

	recv.init(setSize, psiSecParam, ZeroBlock);
	recv.sendInput(recvSet, recvChl);

	thrd.join();

	for (u64 i = 0; i < sendChl.size(); ++i)
	{
		sendChl[0].close();
		recvChl[0].close();
	}

	ep0.stop();
	ep1.stop();
	ios.stop();

	if (recv.mIntersection.size() != 1 ||
		recv.mIntersection[0] != 0)
	{

		throw UnitTestFail();
	}

}