import React from 'react';

export const LobsterBackground: React.FC = () => {
  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden select-none">
      {/* Soft nebula glows */}
      <div className="absolute -top-20 -left-28 w-[38vw] h-[38vw] bg-[#e4c7fd] blur-[140px] opacity-50"></div>
      <div className="absolute top-[10%] right-[-10%] w-[42vw] h-[42vw] bg-[#6100ff] blur-[180px] opacity-10"></div>
      <div className="absolute bottom-[-12%] left-[15%] w-[48vw] h-[48vw] bg-[#b56fed] blur-[200px] opacity-15"></div>
      <div className="absolute top-[40%] right-[20%] w-[35vw] h-[35vw] bg-[#e4c7fd] blur-[160px] opacity-40"></div>

      {/* Angular motif inspired by Prompt "A" */}
      <div className="absolute right-[-5%] bottom-[10%] w-[59.8vw] h-[59.8vw] opacity-85">
        <img
          src="/img/prompt_line.svg"
          loading="lazy"
          alt=""
          className="w-full h-full object-contain"
        />
      </div>
    </div>
  );
};
