import { Router, type IRouter } from "express";
import healthRouter from "./health";
import anthropicRouter from "./anthropic";
import analysisRouter from "./analysis";
import sandboxRouter from "./sandbox";
import modelsRouter from "./models";
import liveCaptureRouter from "./liveCapture";

const router: IRouter = Router();

router.use(healthRouter);
router.use(anthropicRouter);
router.use(analysisRouter);
router.use(sandboxRouter);
router.use(modelsRouter);
router.use(liveCaptureRouter);

export default router;
