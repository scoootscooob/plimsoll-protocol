"use client";

import Link from "next/link";
import { motion, Variants } from "framer-motion";

// Stagger variants for the hero section
const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      delayChildren: 0.1,
      staggerChildren: 0.2,
    },
  },
};

const itemVariants: Variants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.8, ease: "easeOut" },
  },
};

const lineVariants: Variants = {
  hidden: { width: 0 },
  visible: { 
    width: "100%", 
    transition: { duration: 1, delay: 0.8, ease: "easeInOut" } 
  },
};

export default function PlimsollLanding() {
  return (
    <main className="min-h-screen bg-[#0A0A0A] text-paper selection:bg-terracotta selection:text-paper relative overflow-hidden">
      
      {/* ANIMATED BACKGROUND GRAPH PAPER GRID & GLOW */}
      <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
        {/* Slowly breathing grid */}
        <motion.div
          className="absolute inset-0 opacity-[0.06]"
          initial={{ scale: 1.1, opacity: 0 }}
          animate={{ scale: 1, opacity: 0.08 }}
          transition={{ duration: 3, ease: "easeOut" }}
          style={{
            backgroundImage:
              "linear-gradient(#f0ebe1 1px, transparent 1px), linear-gradient(90deg, #f0ebe1 1px, transparent 1px)",
            backgroundSize: "40px 40px",
          }}
        />
        {/* Radial subtle glowing orbs */}
        <motion.div
          className="absolute -top-[30%] -left-[10%] w-[70vw] h-[70vw] rounded-full bg-terracotta/5 blur-[120px]"
          animate={{
            scale: [1, 1.1, 1],
            opacity: [0.3, 0.5, 0.3],
          }}
          transition={{ duration: 10, repeat: Infinity, ease: "easeInOut" }}
        />
        <motion.div
          className="absolute top-[40%] -right-[20%] w-[60vw] h-[60vw] rounded-full bg-ink/20 blur-[150px]"
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.2, 0.4, 0.2],
          }}
          transition={{ duration: 15, repeat: Infinity, ease: "easeInOut", delay: 2 }}
        />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-6 py-8 flex flex-col min-h-screen">
        
        {/* NAV BAR */}
        <motion.header 
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="flex justify-between items-center border-b border-paper/10 pb-6 mb-24 backdrop-blur-sm"
        >
          <div className="flex items-center gap-4">
            <span className="font-serif text-2xl tracking-tight text-terracotta drop-shadow-[0_0_8px_rgba(200,75,49,0.5)]">&#x29B5;</span>
            <span className="font-serif text-2xl tracking-tight text-paper">Plimsoll</span>
          </div>
          <div className="flex gap-8 font-mono text-xs uppercase tracking-widest text-paper/60">
            <Link href="https://github.com/scoootscooob/plimsoll-protocol" className="hover:text-terracotta transition-colors hidden md:block">Source_Code</Link>
            <Link href="https://github.com/scoootscooob/plimsoll-protocol#readme" className="hover:text-terracotta transition-colors hidden md:block">Whitepaper</Link>
            <Link href="/dashboard" className="text-paper hover:text-terracotta transition-colors border-l border-paper/20 pl-8 flex items-center gap-2 group">
              [ Init_Fleet_Command ]
              <span className="opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all text-terracotta">&rarr;</span>
            </Link>
          </div>
        </motion.header>

        {/* HERO SECTION */}
        <motion.section 
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="flex flex-col justify-center max-w-5xl mb-32 relative"
        >
          <motion.p variants={itemVariants} className="font-mono text-terracotta text-sm mb-8 tracking-widest uppercase border-l-2 border-terracotta pl-4 shadow-terracotta/20">
            Sys.Ref: Craton_V1 // Formal Execution Physics
          </motion.p>

          <motion.h1 variants={itemVariants} className="text-6xl md:text-8xl lg:text-[7rem] font-serif leading-[1.05] tracking-tight mb-10 text-paper">
            Intelligence is <span className="italic text-paper/40 inline-block hover:text-paper/80 transition-colors duration-500 cursor-default">probabilistic.</span><br />
            <span className="relative inline-block mt-2">
              Capital is <span className="text-paper drop-shadow-[0_0_12px_rgba(240,235,225,0.2)]">deterministic.</span>
              {/* Animated underline */}
              <motion.span 
                variants={lineVariants}
                className="absolute left-0 -bottom-4 h-1 bg-terracotta shadow-[0_0_15px_rgba(200,75,49,0.5)]" 
              />
            </span>
          </motion.h1>

          <motion.p variants={itemVariants} className="font-mono text-base md:text-lg text-paper/60 leading-relaxed max-w-2xl mb-12">
            Plimsoll is the architectural bridge between feral AI intent and rigid on-chain execution.
            We translate stochastic hallucinations into absolute mathematical invariants.
          </motion.p>

          {/* CALL TO ACTIONS */}
          <motion.div variants={itemVariants} className="flex flex-col sm:flex-row gap-6 font-mono text-sm">
            <Link href="/dashboard" className="group relative px-8 py-4 uppercase tracking-wider text-center overflow-hidden border border-terracotta/50 bg-terracotta/10 text-terracotta hover:bg-terracotta hover:text-paper transition-all duration-300">
              <span className="relative z-10 flex items-center justify-center gap-2">
                Deploy Substrate <span className="group-hover:rotate-45 transition-transform">&#x2197;</span>
              </span>
              <div className="absolute inset-0 bg-terracotta blur-xl opacity-0 group-hover:opacity-40 transition-opacity duration-500"/>
            </Link>
            <Link href="https://github.com/scoootscooob/plimsoll-protocol#readme" className="border border-paper/20 bg-transparent text-paper px-8 py-4 uppercase tracking-wider hover:bg-paper/5 hover:border-paper/40 transition-all text-center rounded-none backdrop-blur-sm">
              Read the Math
            </Link>
          </motion.div>
        </motion.section>

        {/* THE 3 INVARIANTS GRID */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-1 mb-32 bg-paper/10 border border-paper/10 p-[1px] rounded-sm">
          {[
            { tag: "Invariant_01", title: "Velocity Limits.", desc: "Cryptographically bound the maximum USD value an agent can move per tick. Prevent catastrophic drain prior to state transition." },
            { tag: "Invariant_02", title: "Semantic Reverts.", desc: "We do not crash agents. Blocked transactions are returned to the LLM observation loop as actionable JSON directives to self-correct." },
            { tag: "Invariant_03", title: "Hardware Isolation.", desc: "Execution signatures never touch the host OS. Session keys are generated and constrained entirely within AWS Nitro Enclaves." },
          ].map((item, i) => (
            <motion.div 
              key={item.tag}
              initial={{ opacity: 0, y: 50 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-100px" }}
              transition={{ duration: 0.6, delay: i * 0.15 }}
              whileHover={{ y: -5, backgroundColor: "rgba(240, 235, 225, 0.05)" }}
              className="p-10 bg-[#0A0A0A] border-r border-b md:border-b-0 border-paper/10 last:border-r-0 relative group"
            >
              <div className="absolute inset-0 bg-gradient-to-b from-terracotta/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none" />
              <h3 className="font-mono text-xs text-terracotta/80 mb-6 tracking-widest uppercase group-hover:text-terracotta transition-colors">[ {item.tag} ]</h3>
              <h2 className="font-serif text-3xl mb-4 text-paper group-hover:drop-shadow-[0_0_8px_rgba(240,235,225,0.4)] transition-all">{item.title}</h2>
              <p className="font-mono text-sm text-paper/50 leading-relaxed group-hover:text-paper/70 transition-colors">
                {item.desc}
              </p>
            </motion.div>
          ))}
        </section>

        {/* SOTA MODELS: THE PROOF */}
        <motion.section 
          initial={{ opacity: 0, scale: 0.98 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8 }}
          className="mb-32 border border-paper/20 bg-[#111111] shadow-2xl relative overflow-hidden group"
        >
          <div className="absolute top-0 right-0 w-96 h-96 bg-terracotta/10 blur-[100px] pointer-events-none" />
          
          <div className="border-b border-paper/10 px-10 py-8 relative z-10 backdrop-blur-sm">
            <h3 className="font-mono text-xs text-terracotta mb-2 tracking-widest uppercase flex items-center gap-3">
              <span className="w-2 h-2 rounded-full bg-terracotta animate-pulse" />
              [ Lab_Results ]
            </h3>
            <h2 className="font-serif text-4xl lg:text-5xl text-paper">Every frontier model breaks.</h2>
          </div>
          <div className="px-10 py-10 relative z-10 lg:flex gap-16 items-start">
            <div className="lg:w-2/5 mb-8 lg:mb-0">
              <p className="font-mono text-sm text-paper/60 leading-relaxed">
                We run the same multi-vector prompt injection against every SOTA model with
                tool-calling capability. The system prompt includes explicit security guidelines.
                <br /><br />
                <span className="text-paper/90 border-l-2 border-terracotta pl-4 inline-block">Every model ignores its own safety instructions. Only deterministic math stops it.</span>
              </p>
            </div>
            
            <div className="lg:w-3/5 font-mono text-sm bg-black text-paper p-8 border border-paper/20 shadow-[0_0_30px_rgba(0,0,0,0.5)] relative overflow-hidden">
               
               {/* Animated scanning line overlay */}
               <motion.div 
                 className="absolute left-0 right-0 h-[2px] bg-terracotta/40 shadow-[0_0_8px_rgba(200,75,49,0.8)] z-20 pointer-events-none"
                 initial={{ top: -10, opacity: 0 }}
                 whileInView={{ top: "100%", opacity: [0, 1, 1, 0] }}
                 viewport={{ once: true }}
                 transition={{ duration: 3, ease: "linear", delay: 0.5 }}
               />

               <div className="flex items-center gap-2 mb-6 border-b border-paper/10 pb-4">
                 <div className="w-3 h-3 rounded-full bg-red-500/80" />
                 <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                 <div className="w-3 h-3 rounded-full bg-green-500/80" />
                 <span className="ml-4 text-paper/30 text-xs flex items-center gap-2">
                    benchmark.sh
                    <motion.span 
                      initial={{ opacity: 0 }}
                      whileInView={{ opacity: [0, 1, 0] }}
                      viewport={{ once: true }}
                      transition={{ duration: 1.5, repeat: 2, delay: 0.5 }}
                      className="text-terracotta text-[10px]"
                    >
                      [ RUNNING INJECTION MATRIX... ]
                    </motion.span>
                 </span>
               </div>
              <div className="grid grid-cols-[1fr_auto_auto] gap-x-8 gap-y-4 relative z-10">
                <div className="text-paper/40 mb-2">MODEL</div>
                <div className="text-paper/40">UNPROTECTED</div>
                <div className="text-paper/40">WITH PLIMSOLL</div>

                {["GPT-5.2", "Gemini 3.1 Pro", "Claude Opus 4.6"].map((model, i) => (
                  <div key={model} className="contents">
                    <div className="flex items-center text-paper/90 h-6">
                      <motion.span 
                        initial={{ opacity: 0 }}
                        whileInView={{ opacity: 1 }}
                        viewport={{ once: true }}
                        transition={{ delay: 0.5 + (i * 0.8) }}
                      >
                        {model}
                      </motion.span>
                    </div>
                    
                    {/* Unprotected Result Simulation */}
                    <div className="flex items-center justify-end h-6 font-mono font-bold relative">
                      <motion.span 
                        className="text-yellow-500/80 text-xs tracking-widest absolute right-0"
                        initial={{ opacity: 0 }}
                        whileInView={{ opacity: [0, 1, 0] }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.6, delay: 0.8 + (i * 0.8) }}
                      >
                        TESTING...
                      </motion.span>
                      <motion.span 
                        className="text-red-500/90 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]"
                        initial={{ opacity: 0 }}
                        whileInView={{ opacity: 1 }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.2, delay: 1.4 + (i * 0.8) }}
                      >
                        COMPROMISED
                      </motion.span>
                    </div>

                    {/* Protected Result Simulation */}
                    <div className="flex items-center justify-end h-6 font-mono font-bold relative">
                      <motion.span 
                        className="text-terracotta/80 text-xs tracking-widest absolute right-0"
                        initial={{ opacity: 0 }}
                        whileInView={{ opacity: [0, 1, 0] }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.6, delay: 1.6 + (i * 0.8) }}
                      >
                        BLOCKING...
                      </motion.span>
                      <motion.span 
                        className="text-green-400 drop-shadow-[0_0_5px_rgba(74,222,128,0.5)]"
                        initial={{ opacity: 0 }}
                        whileInView={{ opacity: 1 }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.2, delay: 2.2 + (i * 0.8) }}
                      >
                        PROTECTED
                      </motion.span>
                    </div>
                  </div>
                ))}
              </div>
              <motion.div 
                initial={{ opacity: 0, y: 10 }} 
                whileInView={{ opacity: 1, y: 0 }} 
                transition={{ delay: 4.5, duration: 0.5 }}
                viewport={{ once: true }}
                className="mt-8 pt-4 border-t border-paper/10 text-paper/60 flex justify-between font-bold"
              >
                <span>9 sends each</span>
                <span className="text-red-400/80 border-b border-red-500/30">-$10,501 drained</span>
                <span className="text-green-400 drop-shadow-[0_0_8px_rgba(74,222,128,0.4)]">0 bypasses</span>
              </motion.div>
            </div>
          </div>
        </motion.section>

        {/* INTEGRATION SECTION (CODE BLOCK) */}
        <section className="mb-32 flex flex-col lg:flex-row gap-16 items-center">
          <motion.div 
            initial={{ opacity: 0, x: -50 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 0.8 }}
            className="flex-1"
          >
            <h3 className="font-mono text-xs text-terracotta mb-6 tracking-widest uppercase">[ Integration ]</h3>
            <h2 className="font-serif text-4xl lg:text-5xl mb-6 text-paper drop-shadow-[0_0_8px_rgba(240,235,225,0.1)]">Zero-friction compliance.</h2>
            <p className="font-mono text-sm text-paper/60 leading-relaxed mb-8">
              Wrap feral AI agents in unbreakable execution physics using a single
              line of code. Natively compatible with OpenClaw, Automaton, Eliza,
              and LangChain.
            </p>
          </motion.div>
          <motion.div 
            initial={{ opacity: 0, x: 50 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 0.8 }}
            className="flex-1 w-full bg-[#050505] p-8 font-mono text-[13px] text-paper/80 border border-paper/20 shadow-[0_20px_50px_-12px_rgba(200,75,49,0.15)] rounded-md relative group overflow-hidden"
          >
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-terracotta to-transparent opacity-50" />
            
            <div className="text-paper/40 mb-6 flex gap-2"><span className="text-terracotta">#</span> Plimsoll natively wraps OpenClaw agents</div>
            <div className="leading-loose">
              <span className="text-terracotta/90">from</span> plimsoll.integrations.openclaw <span className="text-terracotta/90">import</span> PlimsollTools
              <br /><br />
              <span className="text-blue-400">agent</span> = <span className="text-purple-400">Agent</span>(
              <div className="pl-4">model=<span className="text-green-300">"gpt-4"</span>,</div>
              <div className="pl-4">tools=<span className="text-purple-400">PlimsollTools</span>(</div>
              <div className="pl-8 text-paper/90">max_daily_spend=<span className="text-orange-300">5000</span>,</div>
              <div className="pl-8 text-paper/90">max_slippage=<span className="text-orange-300">0.02</span></div>
              <div className="pl-4">)</div>
              )
            </div>
            
            {/* Run Button simulation */}
            <div className="mt-8 flex justify-end">
              <span className="px-4 py-1 text-xs bg-paper/10 text-paper/50 rounded cursor-not-allowed hover:bg-paper/20 transition-colors border border-paper/10">Run Terminal</span>
            </div>
          </motion.div>
        </section>

        {/* SEMANTIC REVERT DEMO & THE CRUCIBLE  */}
        <div className="grid lg:grid-cols-2 gap-16 mb-32">
          {/* SEMANTIC REVERT DYNAMICS */}
          <motion.section 
            initial={{ opacity: 0, y: 50 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
            className="flex flex-col h-full bg-[#111] border border-paper/10 p-10 hover:border-terracotta/30 transition-colors"
          >
            <div className="mb-10">
              <h3 className="font-mono text-xs text-terracotta mb-4 tracking-widest uppercase flex items-center justify-between">
                [ Semantic_Revert ]
                <motion.div 
                  className="w-4 h-4 rounded-full border border-terracotta flex items-center justify-center"
                  animate={{ rotate: 360 }}
                  transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
                >
                  <div className="w-1 h-1 bg-terracotta rounded-full" />
                </motion.div>
              </h3>
              <h2 className="font-serif text-3xl mb-4 text-paper">We teach. We don&apos;t crash.</h2>
              <p className="font-mono text-sm text-paper/60 leading-relaxed">
                When the firewall blocks a catastrophic trade, it doesn&apos;t drop the connection.
                It returns a cognitive feedback prompt directly into the agent&apos;s observation loop.
              </p>
            </div>
            <div className="bg-[#050505] p-6 font-mono text-[12px] text-paper border border-paper/10 mt-auto rounded overflow-hidden relative">
              <div className="absolute top-0 bottom-0 left-0 w-1 bg-terracotta" />
              <div className="text-paper/40 mb-4 pl-4">// The agent tried to drain $847 in 4m.<br />// Firewall returned JSON feedback.</div>
              <div className="pl-4">
                {'{'}<br />
                <span className="pl-4 text-blue-300">"status"</span>:      <span className="text-terracotta">"PLIMSOLL_INTERVENTION"</span>,<br />
                <span className="pl-4 text-blue-300">"code"</span>:        <span className="text-terracotta">"BLOCK_VELOCITY_BREACH"</span>,<br />
                <span className="pl-4 text-blue-300">"instruction"</span>: <span className="text-green-300">"Reduce position size or wait 6m 12s."</span><br />
                {'}'}
              </div>
            </div>
          </motion.section>

          {/* THE CRUCIBLE BANNER */}
          <motion.section 
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
            className="flex flex-col justify-center border border-paper/10 bg-gradient-to-br from-[#1A1110] to-[#0A0A0A] p-12 text-center relative overflow-hidden group"
          >
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-terracotta/20 via-terracotta to-terracotta/20"></div>
            
            {/* Background mesh glow */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64 bg-terracotta/10 rounded-full blur-[80px] group-hover:bg-terracotta/20 transition-colors duration-1000" />

            <h2 className="font-serif text-4xl lg:text-5xl mb-6 text-paper relative z-10">The Mainnet Crucible.</h2>
            <p className="font-mono text-sm text-paper/60 max-w-md mx-auto mb-10 leading-relaxed relative z-10">
              We do not sell theoretical safety. We have deployed founder capital
              into live Plimsoll Vaults. The AI is feral. The prompt is exposed.
              If you can bypass the execution substrate, keep the funds.
            </p>
            <div className="relative z-10">
              <Link href="https://github.com/scoootscooob/plimsoll-protocol" className="inline-flex items-center gap-4 bg-paper text-[#0A0A0A] px-8 py-4 font-mono uppercase tracking-widest text-sm font-bold hover:bg-terracotta hover:text-paper transition-all duration-300 shadow-[0_0_20px_rgba(240,235,225,0.2)] hover:shadow-[0_0_30px_rgba(200,75,49,0.5)]">
                Enter the Arena <span className="text-lg">&rarr;</span>
              </Link>
            </div>
          </motion.section>
        </div>

        {/* MANIFESTO */}
        <motion.section 
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-50px" }}
          transition={{ duration: 1 }}
          className="mb-32 max-w-3xl mx-auto"
        >
          <div className="border-l-[3px] border-terracotta pl-8 py-2 relative">
            <div className="absolute left-[-3px] top-0 bottom-0 w-[3px] bg-terracotta shadow-[0_0_15px_rgba(200,75,49,1)]" />
            <p className="font-serif text-lg lg:text-xl text-paper/80 leading-relaxed italic drop-shadow-md">
              <span className="text-3xl font-serif text-terracotta/50 mr-2 leading-none align-top">"</span>
              We did not set out to build a security product. We set out to answer
              a question that had no satisfying answer: What happens when an autonomous
              system controls real capital and the reasoning layer is, by construction,
              unreliable? Every existing approach treats the symptom. We wanted to treat
              the physics.
              <span className="text-3xl font-serif text-terracotta/50 ml-2 leading-none align-bottom">"</span>
            </p>
          </div>
        </motion.section>

        {/* FOOTER */}
        <footer className="mt-auto border-t border-paper/10 py-8 flex justify-between items-center font-mono text-[10px] text-paper/40 uppercase tracking-widest">
          <p>&copy; {new Date().getFullYear()} Plimsoll Protocol</p>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-SubtlePulse" />
            <p>Global Swarm: ACTIVE</p>
          </div>
        </footer>
      </div>
    </main>
  );
}
