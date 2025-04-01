
import BitcoinConverter from "@/components/BitcoinConverter";

const Index = () => {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-b from-background to-muted p-4">
      <div className="w-full max-w-lg">
        <BitcoinConverter />
      </div>
    </div>
  );
};

export default Index;
