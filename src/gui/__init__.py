"""preflight 게이트의 GUI 프론트엔드.

핵심 판정 로직(spawn_suspended -> 분석 -> resume/terminate)은 preflight.pipeline.run()에
그대로 있고, 여기서는 그 함수의 prompt 콜백 자리에 GUI 확인창을 꽂아 넣기만 한다
(__main__.prompt_user가 input()을 꽂는 것과 동일한 자리).
"""
